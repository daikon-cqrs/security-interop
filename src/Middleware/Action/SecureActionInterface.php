<?php declare(strict_types=1);
/**
 * This file is part of the daikon-cqrs/security-interop project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Daikon\Security\Middleware\Action;

use Daikon\Boot\Middleware\Action\ActionInterface;
use Daikon\Boot\Middleware\Action\DaikonRequest;

interface SecureActionInterface extends ActionInterface
{
    public function isAuthorized(DaikonRequest $request): bool;

    public function isSecure(): bool;
}
