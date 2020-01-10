<?php declare(strict_types=1);
/**
 * This file is part of the oroshi/security-interop project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Oroshi\Security\Authorization;

use Auryn\Injector;
use Daikon\Config\ConfigProviderInterface;
use Oroshi\Core\Service\ServiceDefinitionInterface;
use Oroshi\Core\Service\Provisioner\ProvisionerInterface;
use Zend\Permissions\Acl\Acl;
use Zend\Permissions\Acl\Assertion\AssertionInterface;
use Zend\Permissions\Acl\Assertion\ExpressionAssertion;

final class ZendAclProvisioner implements ProvisionerInterface
{
    public function provision(
        Injector $injector,
        ConfigProviderInterface $configProvider,
        ServiceDefinitionInterface $serviceDefinition
    ): void {
        $className = $serviceDefinition->getServiceClass();
        $settings = $serviceDefinition->getSettings();
        $roles = $settings['roles'] ?? [];
        $resources = $settings['resources'] ?? [];

        $injector
            ->alias(AuthorizationServiceInterface::class, $className)
            ->share($className)
            ->delegate(
                $className,
                function () use ($className, $roles, $resources): AuthorizationServiceInterface {
                    $acl = new Acl;
                    array_map([$acl, 'addRole'], array_keys($roles), $roles);
                    array_map([$acl, 'addResource'], array_keys($resources));
                    foreach ($resources as $resource => $rules) {
                        $allows = $rules['allow'] ?? [];
                        $denies = $rules['deny'] ?? [];
                        //@todo support registration order for rule types
                        $this->registerRules($acl, Acl::TYPE_ALLOW, $allows, $roles, $resource);
                        $this->registerRules($acl, Acl::TYPE_DENY, $denies, $roles, $resource);
                    }
                    /** @var AuthorizationServiceInterface */
                    return new $className($acl);
                }
            );
    }

    private function registerRules(Acl &$acl, string $type, array $rules, array $roles, string $resource = null): void
    {
        foreach ($rules as $rule) {
            $ruleRoles = (array)($rule['roles'] ?? array_keys($roles));
            $assertions = (array)($rule['asserts'] ?? [null]);
            $privileges = $rule['privileges'] ?? null;
            foreach ($this->buildAssertions($assertions) as $assertion) {
                $acl->setRule(Acl::OP_ADD, $type, $ruleRoles, $resource, $privileges, $assertion);
            }
        }
    }

    private function buildAssertions(array $asserts): array
    {
        $assertions = [];
        array_push($assertions, ...array_map([$this, 'buildAssertion'], $asserts));
        return $assertions;
    }

    /** @param mixed $assert */
    private function buildAssertion($assert = null): ?AssertionInterface
    {
        $assertion = null;
        if (is_string($assert)) {
            /** @var AssertionInterface $assertion */
            $assertion = new $assert;
        } elseif (is_array($assert)) {
            /** @var AssertionInterface $assertion */
            $assertion = ExpressionAssertion::fromProperties(
                [ExpressionAssertion::OPERAND_CONTEXT_PROPERTY => $assert[0]],
                $assert[1],
                $this->resolveOperandValue($assert[2])
            );
        }
        return $assertion;
    }

    /**
     * @param mixed|array $operand
     * @return mixed
     */
    private function resolveOperandValue($operand)
    {
        if (is_callable($operand) === true) {
            return $operand();
        }
        return $operand;
    }
}
