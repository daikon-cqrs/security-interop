<?php declare(strict_types=1);
/**
 * This file is part of the daikon-cqrs/security-interop project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Daikon\Security\Middleware\Action;

use Daikon\Boot\Middleware\Action\Action;
use Daikon\Boot\Middleware\Action\DaikonRequest;

abstract class SecureAction extends Action implements SecureActionInterface
{
    public function isAuthorized(DaikonRequest $request): bool
    {
        return false;
    }

    public function isSecure(): bool
    {
        return true;
    }
}
