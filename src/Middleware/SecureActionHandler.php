<?php declare(strict_types=1);
/**
 * This file is part of the daikon-cqrs/security-interop project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Daikon\Security\Middleware;

use Daikon\Boot\Middleware\Action\ActionInterface;
use Daikon\Boot\Middleware\Action\ResponderInterface;
use Daikon\Boot\Middleware\Action\ValidatorInterface;
use Daikon\Boot\Middleware\ActionHandler;
use Daikon\Boot\Middleware\ResolvesDependency;
use Daikon\Boot\Middleware\RoutingHandler;
use Daikon\Interop\AssertionFailedException;
use Daikon\Interop\RuntimeException;
use Daikon\Security\Exception\AuthenticationException;
use Daikon\Security\Exception\AuthorizationException;
use Daikon\Security\Middleware\Action\SecureActionInterface;
use Exception;
use Fig\Http\Message\StatusCodeInterface;
use Middlewares\Utils\Factory;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

final class SecureActionHandler implements MiddlewareInterface, StatusCodeInterface
{
    use ResolvesDependency;

    private ContainerInterface $container;

    private LoggerInterface $logger;

    public function __construct(ContainerInterface $container, LoggerInterface $logger)
    {
        $this->container = $container;
        $this->logger = $logger;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $requestHandler = $request->getAttribute(RoutingHandler::ATTR_REQUEST_HANDLER);
        return $requestHandler instanceof ActionInterface
            ? $this->executeAction($requestHandler, $request)
            : $handler->handle($request);
    }

    private function executeAction(ActionInterface $action, ServerRequestInterface $request): ResponseInterface
    {
        // Check action access first before running validation
        if ($action instanceof SecureActionInterface) {
            if (!$action->isAuthorized($request)) {
                return Factory::createResponse(self::STATUS_FORBIDDEN);
            }
        }

        $request = $action->registerValidator($request);
        if ($validator = $this->getValidator($request)) {
            $request = $validator($request);
        }

        if (!empty($request->getAttribute(ActionHandler::ATTR_ERRORS))) {
            $request = $action->handleError(
                $request->withAttribute(
                    ActionHandler::ATTR_STATUS_CODE,
                    $request->getAttribute(ActionHandler::ATTR_STATUS_CODE, self::STATUS_UNPROCESSABLE_ENTITY)
                )
            );
        } else {
            // Run secondary resource authorization after validation
            if ($action instanceof SecureActionInterface) {
                if (!$action->isAuthorized($request)) {
                    return Factory::createResponse(self::STATUS_FORBIDDEN);
                }
            }

            try {
                $request = $action($request);
            } catch (Exception $error) {
                $this->logger->error($error->getMessage(), ['trace' => $error->getTrace()]);
                switch (true) {
                    case $error instanceof AssertionFailedException:
                        $statusCode = self::STATUS_UNPROCESSABLE_ENTITY;
                        break;
                    case $error instanceof AuthenticationException:
                        $statusCode = self::STATUS_UNAUTHORIZED;
                        break;
                    case $error instanceof AuthorizationException:
                        $statusCode = self::STATUS_FORBIDDEN;
                        break;
                    default:
                        $statusCode = self::STATUS_INTERNAL_SERVER_ERROR;
                }
                $request = $action->handleError(
                    $request
                        ->withAttribute(ActionHandler::ATTR_STATUS_CODE, $statusCode)
                        ->withAttribute(ActionHandler::ATTR_ERRORS, $error)
                );
            }
        }
        if (!$responder = $this->getResponder($request)) {
            throw $error ?? new RuntimeException(
                sprintf("Unable to determine responder for '%s'.", get_class($action))
            );
        }

        return $responder($request);
    }

    private function getValidator(ServerRequestInterface $request): ?callable
    {
        return ($validator = $request->getAttribute(ActionHandler::ATTR_VALIDATOR))
            ? $this->resolve($this->container, $validator, ValidatorInterface::class)
            : null;
    }

    private function getResponder(ServerRequestInterface $request): ?callable
    {
        return ($responder = $request->getAttribute(ActionHandler::ATTR_RESPONDER))
            ? $this->resolve($this->container, $responder, ResponderInterface::class)
            : null;
    }
}
