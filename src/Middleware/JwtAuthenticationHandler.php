<?php declare(strict_types=1);
/**
 * This file is part of the daikon-cqrs/security-interop project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Daikon\Security\Middleware;

use Daikon\Boot\Middleware\RoutingHandler;
use Daikon\Config\ConfigProviderInterface;
use Daikon\Interop\Assertion;
use Daikon\Security\Authentication\AuthenticatorInterface;
use Daikon\Security\Authentication\JwtAuthenticationServiceInterface;
use Daikon\Security\Exception\AuthenticationException;
use Daikon\Security\Middleware\Action\SecureActionInterface;
use Fig\Http\Message\StatusCodeInterface;
use Middlewares\Utils\Factory;
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
            is_a($authConfig['default_role'], AuthenticatorInterface::class, true),
            sprintf("Authentication default role must implement '%s'.", AuthenticatorInterface::class)
        );
        $jwtAttribute = $authConfig['jwt']['attribute'] ?? JwtDecoder::DEFAULT_ATTR_JWT;
        $xsrfAttribute = $authConfig['xsrf']['attribute'] ?? JwtDecoder::DEFAULT_ATTR_XSRF;

        $jwt = $request->getAttribute($jwtAttribute);
        $xsrfToken = $request->getAttribute($xsrfAttribute);

        try {
            if ($this->isSecure($request)) {
                if (!$jwt) {
                    throw new AuthenticationException('Missing JWT.');
                }
                if (!$xsrfToken) {
                    throw new AuthenticationException('Missing XSRF token.');
                }
            }

            if ($jwt) {
                if (!$jwt->uid || !$jwt->jti) {
                    throw new AuthenticationException('Invalid JWT.');
                }
                if ($jwt->xsrf !== $xsrfToken) {
                    throw new AuthenticationException('XSRF token does not match JWT.');
                }
                /** @var AuthenticatorInterface $authenticator */
                $authenticator = $this->authenticationService->authenticateJWT($jwt->uid, $jwt->jti, $jwt->xsrf);
            }
        } catch (AuthenticationException $error) {
            return Factory::createResponse(self::STATUS_UNAUTHORIZED);
        }

        return $handler->handle(
            $request->withAttribute(self::ATTR_AUTHENTICATOR, $authenticator ?? new $authConfig['default_role'])
        );
    }

    private function isSecure(ServerRequestInterface $request): bool
    {
        $requestHandler = $request->getAttribute(RoutingHandler::ATTR_REQUEST_HANDLER);
        return $requestHandler instanceof SecureActionInterface
            ? $requestHandler->isSecure()
            : false;
    }
}
