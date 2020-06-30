<?php declare(strict_types=1);
/**
 * This file is part of the daikon-cqrs/security-interop project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Daikon\Tests\Security\Middleware;

use Daikon\Config\ConfigProviderInterface;
use Daikon\Security\Middleware\JwtDecoder;
use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class JwtDecoderTest extends TestCase
{
    public function testEmptyAuth(): void
    {
        $config = $this->createMock(ConfigProviderInterface::class);
        $config->expects($this->once())->method('get')->with('project.authentication')->willReturn([]);
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getCookieParams')->willReturn(null);
        $request->expects($this->exactly(2))->method('getHeaderLine')->willReturn('');
        $request->expects($this->exactly(2))->method('withAttribute')->willReturnSelf();
        $handler = $this->createMock(RequestHandlerInterface::class);
        /**
         * @var ConfigProviderInterface $config
         * @var ServerRequestInterface $request
         * @var RequestHandlerInterface $handler
         */
        $decoder = new JwtDecoder($config);
        $decoder->process($request, $handler);
    }

    public function testHeaderAuthWithInvalidJwt(): void
    {
        $config = $this->createMock(ConfigProviderInterface::class);
        $config->expects($this->at(0))->method('get')->with('project.authentication')->willReturn([]);
        $config->expects($this->at(1))->method('get')->with('project.authentication.jwt.secret')->willReturn('key');
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->at(0))->method('getCookieParams')->willReturn(null);
        $request->expects($this->at(1))->method('getHeaderLine')->with('Authorization')->willReturn('Bearer xyz');
        $request->expects($this->at(2))->method('getHeaderLine')->with('X-XSRF-TOKEN')->willReturn('xsrf');
        $request->expects($this->at(3))->method('withAttribute')->with('__Host-_jwt', null)->willReturnSelf();
        $request->expects($this->at(4))->method('withAttribute')->with('__Host-_xsrf', 'xsrf')->willReturnSelf();
        $handler = $this->createMock(RequestHandlerInterface::class);
        /**
         * @var ConfigProviderInterface $config
         * @var ServerRequestInterface $request
         * @var RequestHandlerInterface $handler
         */
        $decoder = new JwtDecoder($config);
        $decoder->process($request, $handler);
    }

    public function testHeaderAuthWithValidJwt(): void
    {
        $jwt = JWT::encode(['iss' => 'test', 'xsrf' => 'xsrf'], 'key');
        $decodedJwt = JWT::decode($jwt, 'key', ['HS256']);
        $config = $this->createMock(ConfigProviderInterface::class);
        $config->expects($this->at(0))->method('get')->with('project.authentication')->willReturn([]);
        $config->expects($this->at(1))->method('get')->with('project.authentication.jwt.secret')->willReturn('key');
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->at(0))->method('getCookieParams')->willReturn(null);
        $request->expects($this->at(1))->method('getHeaderLine')->with('Authorization')->willReturn("Bearer $jwt");
        $request->expects($this->at(2))->method('getHeaderLine')->with('X-XSRF-TOKEN')->willReturn('xsrf');
        $request->expects($this->at(3))->method('withAttribute')->with('__Host-_jwt', $decodedJwt)->willReturnSelf();
        $request->expects($this->at(4))->method('withAttribute')->with('__Host-_xsrf', 'xsrf')->willReturnSelf();
        $handler = $this->createMock(RequestHandlerInterface::class);
        /**
         * @var ConfigProviderInterface $config
         * @var ServerRequestInterface $request
         * @var RequestHandlerInterface $handler
         */
        $decoder = new JwtDecoder($config);
        $decoder->process($request, $handler);
    }
}
