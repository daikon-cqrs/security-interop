<?php declare(strict_types=1);
/**
 * This file is part of the daikon-cqrs/security-interop project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Daikon\Security\Authentication;

interface AuthenticatorInterface
{
    /**
     * @todo consider introducing a state interface
     * @return mixed
     */
    public function getState();
}
