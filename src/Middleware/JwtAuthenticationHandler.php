<?php declare(strict_types=1);
/**
 * This file is part of the oroshi/security-interop project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Oroshi\Security\Middleware;

use Assert\Assertion;
use Daikon\Config\ConfigProviderInterface;
use Fig\Http\Message\StatusCodeInterface;
use Middlewares\Utils\Factory;
use Oroshi\Core\Middleware\Action\SecureActionInterface;
use Oroshi\Core\Middleware\RoutingHandler;
use Oroshi\Security\Authentication\AuthenticatorInterface;
use Oroshi\Security\Authentication\JwtAuthenticationServiceInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class JwtAuthenticationHandler implements MiddlewareInterface, StatusCodeInterface
{
    public const ATTR_AUTHENTICATOR = '_authenticator';

    private ConfigProviderInterface $config;

    private JwtAuthenticationServiceInterface $authenticationService;

    public function __construct(
        ConfigProviderInterface $config,
        JwtAuthenticationServiceInterface $authenticationService
    ) {
        $this->config = $config;
        $this->authenticationService = $authenticationService;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $authConfig = $this->config->get('project.authentication', []);
        Assertion::true(
            is_a($authConfig['defaultRole'], AuthenticatorInterface::class, true),
            'Authentication default role must be an instance of '.AuthenticatorInterface::class
        );
        $jwtAttribute = $authConfig['jwt']['attribute'] ?? JwtDecoder::DEFAULT_ATTR_JWT;
        $xsrfAttribute = $authConfig['xsrf']['attribute'] ?? JwtDecoder::DEFAULT_ATTR_XSRF;

        $jwt = $request->getAttribute($jwtAttribute);
        $xsrfToken = $request->getAttribute($xsrfAttribute);

        if ($this->isSecure($request)) {
            if (!$jwt) {
                return $this->buildResponse(self::STATUS_FORBIDDEN, 'Missing JWT.');
            }
            if (!$xsrfToken) {
                return $this->buildResponse(self::STATUS_FORBIDDEN, 'Missing XSRF token.');
            }
        }

        if ($jwt) {
            if (!$jwt->uid) {
                return $this->buildResponse(self::STATUS_FORBIDDEN, 'Invalid JWT.');
            }
            if ($jwt->xsrf !== $xsrfToken) {
                return $this->buildResponse(self::STATUS_UNAUTHORIZED, 'XSRF token does not match JWT.');
            }

            /** @var AuthenticatorInterface $authenticator */
            $authenticator = $this->authenticationService->authenticateJWT($jwt->uid, $jwt->jti, $jwt->xsrf);
        }

        return $handler->handle(
            $request->withAttribute(self::ATTR_AUTHENTICATOR, $authenticator ?? new $authConfig['defaultRole'])
        );
    }

    private function isSecure(ServerRequestInterface $request): bool
    {
        $requestHandler = $request->getAttribute(RoutingHandler::ATTR_HANDLER);
        return !empty($requestHandler) && $requestHandler instanceof SecureActionInterface
            ? $requestHandler->isSecure()
            : false;
    }

    private function buildResponse(int $code, string $message = null): ResponseInterface
    {
        $response = Factory::createResponse($code);
        if (!empty($message)) {
            $response->getBody()->write(json_encode(['message' => $message]));
        }
        return $response;
    }
}
