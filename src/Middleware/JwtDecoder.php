<?php declare(strict_types=1);
/**
 * This file is part of the daikon-cqrs/security-interop project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Daikon\Security\Middleware;

use Daikon\Config\ConfigProviderInterface;
use Daikon\Interop\Assertion;
use Firebase\JWT\JWT;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use UnexpectedValueException;

final class JwtDecoder implements MiddlewareInterface
{
    public const DEFAULT_ATTR_JWT = '__Host-_jwt';
    public const DEFAULT_ATTR_XSRF = '__Host-_xsrf';
    public const DEFAULT_HEADER_XSRF = 'X-XSRF-TOKEN';

    private ConfigProviderInterface $config;

    public function __construct(ConfigProviderInterface $config)
    {
        $this->config = $config;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $authConfig = $this->config->get('project.authentication', []);
        $jwtAttribute = $authConfig['cookies']['jwt']['attribute'] ?? self::DEFAULT_ATTR_JWT;
        $xsrfAttribute = $authConfig['cookies']['xsrf']['attribute'] ?? self::DEFAULT_ATTR_XSRF;
        $xsrfHeader = $authConfig['cookies']['xsrf']['header'] ?? self::DEFAULT_HEADER_XSRF;

        $cookieParams = $request->getCookieParams();
        $encodedJwt = $cookieParams[$jwtAttribute] ?? $this->parseAuthHeader($request->getHeaderLine('Authorization'));
        $xsrfToken = $cookieParams[$xsrfAttribute] ?? $request->getHeaderLine($xsrfHeader);

        $decodedJwt = $encodedJwt ? $this->decodeJwt($encodedJwt) : null;

        return $handler->handle(
            $request->withAttribute($jwtAttribute, $decodedJwt)->withAttribute($xsrfAttribute, $xsrfToken)
        );
    }

    private function decodeJwt(string $jwt): ?object
    {
        $secretKey = $this->config->get('project.authentication.cookies.jwt.secret');
        Assertion::notBlank($secretKey, 'A jwt secret encoding key is required.');

        try {
            return JWT::decode($jwt, $secretKey, ['HS256']);
        } catch (UnexpectedValueException $error) {
            return null;
        }
    }

    private function parseAuthHeader(string $header): ?string
    {
        return preg_match('/^Bearer\s+(?<token>[\w\.-]+)$/i', $header, $matches)
            ? $matches['token']
            : null;
    }
}
