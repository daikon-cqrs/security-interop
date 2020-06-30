<?php declare(strict_types=1);
/**
 * This file is part of the daikon-cqrs/security-interop project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Daikon\Security\Authorization;

use Laminas\Permissions\Acl\AclInterface;
use Laminas\Permissions\Acl\Resource\ResourceInterface;
use Laminas\Permissions\Acl\Role\RoleInterface;

final class LaminasAclService implements AuthorizationServiceInterface
{
    private AclInterface $acl;

    public function __construct(AclInterface $acl)
    {
        $this->acl = $acl;
    }

    /**
     * @param null|RoleInterface $role
     * @param null|ResourceInterface $resource
     * @param null|string $privilege
     */
    public function isAllowed($role = null, $resource = null, $privilege = null): bool
    {
        return $this->acl->isAllowed($role, $resource, $privilege);
    }
}
