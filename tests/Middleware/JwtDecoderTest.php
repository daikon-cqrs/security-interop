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
        $config->expects($this->exactly(2))
            ->method('get')
            ->withConsecutive(['project.authentication'], ['project.authentication.cookies.jwt.secret'])
            ->willReturnOnConsecutiveCalls([], 'key');
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getCookieParams')->willReturn(null);
        $request->expects($this->exactly(2))
            ->method('getHeaderLine')
            ->withConsecutive(['Authorization'], ['X-XSRF-TOKEN'])
            ->willReturnOnConsecutiveCalls('Bearer xyz', 'xsrf');
        $request->expects($this->exactly(2))
            ->method('withAttribute')
            ->withConsecutive(['__Host-_jwt', null], ['__Host-_xsrf', 'xsrf'])
            ->willReturnSelf();
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
        $config->expects($this->exactly(2))
            ->method('get')
            ->withConsecutive(['project.authentication'], ['project.authentication.cookies.jwt.secret'])
            ->willReturnOnConsecutiveCalls([], 'key');
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getCookieParams')->willReturn(null);
        $request->expects($this->exactly(2))
            ->method('getHeaderLine')
            ->withConsecutive(['Authorization'], ['X-XSRF-TOKEN'])
            ->willReturnOnConsecutiveCalls("Bearer $jwt", 'xsrf');
        $request->expects($this->exactly(2))
            ->method('withAttribute')
            ->withConsecutive(['__Host-_jwt', $decodedJwt], ['__Host-_xsrf', 'xsrf'])
            ->willReturnSelf();
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
