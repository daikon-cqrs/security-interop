<?php declare(strict_types=1);
/**
 * This file is part of the daikon-cqrs/security-interop project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Daikon\Security\Authentication;

final class Unauthenticated implements LaminasAclAuthenticatorInterface
{
    public function getRoleId(): string
    {
        return 'unauthenticated';
    }

    public function getState(): string
    {
        return 'unregistered';
    }
}
