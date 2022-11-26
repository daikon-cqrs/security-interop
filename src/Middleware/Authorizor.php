<?php declare(strict_types=1);
/**
 * This file is part of the daikon-cqrs/security-interop project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Daikon\Security\Middleware;

use Daikon\Boot\Middleware\Action\DaikonRequest;
use Daikon\Boot\Middleware\RoutingHandler;
use Daikon\Security\Middleware\Action\SecureActionInterface;
use Fig\Http\Message\StatusCodeInterface;
use Middlewares\Utils\Factory;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class Authorizor implements MiddlewareInterface, StatusCodeInterface
{
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $requestHandler = $request->getAttribute(RoutingHandler::REQUEST_HANDLER);

        if ($requestHandler instanceof SecureActionInterface) {
            if (!$requestHandler->isAuthorized(DaikonRequest::wrap($request))) {
                return Factory::createResponse(self::STATUS_FORBIDDEN);
            }
        }

        return $handler->handle($request);
    }
}
