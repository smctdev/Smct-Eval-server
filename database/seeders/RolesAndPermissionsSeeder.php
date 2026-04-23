<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\PermissionRegistrar;

class RolesAndPermissionsSeeder extends Seeder
{
    public function run()
    {
        app()[PermissionRegistrar::class]->forgetCachedPermissions();

        // Create permissions
        //employee role
        Permission::create(['name' => 'view_own_profile']);
        Permission::create(['name' => 'view_own_evaluations']);
        Permission::create(['name' => 'submit_self_assessment']);

        //hr and hr-manager role
        Permission::create(['name' => 'view_all_profiles']);
        Permission::create(['name' => 'manage_evaluations']);
        Permission::create(['name' => 'generate_reports']);
        Permission::create(['name' => 'manage_users']);
        Permission::create(['name' => 'view_hr_reports']);

        Permission::create(['name' => 'approve_hr_actions']);
        Permission::create(['name' => 'manage_hr_policies']);

        //evaluator role
        Permission::create(['name' => 'view_evaluation_reports']);
        Permission::create(['name' => 'manage_evaluation_templates']);
        Permission::create(['name' => 'conduct_evaluations']);

        //admin role
        Permission::create(['name' => 'system_administration']);
        Permission::create(['name' => 'user_management']);

        // Create roles and assign created permissions
        $role_employee = Role::create(['name' => 'employee']);
        $role_employee->givePermissionTo('view_own_profile');
        $role_employee->givePermissionTo('view_own_evaluations');
            $role_employee->givePermissionTo('submit_self_assessment');

        $role_hr_manager = Role::create(['name' => 'hr']);
        $role_hr_manager->givePermissionTo('view_all_profiles');
        $role_hr_manager->givePermissionTo('manage_evaluations');
        $role_hr_manager->givePermissionTo('generate_reports');
        $role_hr_manager->givePermissionTo('manage_users');
        $role_hr_manager->givePermissionTo('view_hr_reports');
        $role_hr_manager->givePermissionTo('approve_hr_actions');
        $role_hr_manager->givePermissionTo('manage_hr_policies');

        $role_evaluator = Role::create(['name' => 'evaluator']);
        $role_evaluator->givePermissionTo('conduct_evaluations');
        $role_evaluator->givePermissionTo('view_evaluation_reports');
        $role_evaluator->givePermissionTo('manage_evaluation_templates');

        $role_admin = Role::create(['name' => 'admin']);
        $role_admin->givePermissionTo(Permission::all());
        $role_admin->givePermissionTo('system_administration');
        $role_admin->givePermissionTo('user_management');

        $admin = [
            'position_id'       => 11,
            'department_id'     => null,
            'branch_id'         => 126,
            'username'          => 'admin',
            'fname'             => 'System',
            'lname'             => 'Administrator',
            'email'             => 'admin@smct.com',
            'contact'           => '09'.str_pad(rand(0,999999999), 9, '0', STR_PAD_LEFT ),
            'password'          => 'password',
            'is_active'         => 'active',
            'date_hired'        =>  now(),
            'emp_id'            => str_pad(rand(0,9999999999), 10, '0', STR_PAD_LEFT )
        ];

        $hr = [
            'position_id'       => 82,
            'department_id'     => null,
            'branch_id'         => 126,
            'username'          => 'hr',
            'fname'             => 'HR',
            'lname'             => 'Administrator',
            'email'             => 'hr@smct.com',
            'contact'           => '09'.str_pad(rand(0,999999999), 9, '0', STR_PAD_LEFT ),
            'password'          => 'password',
            'is_active'         => 'active',
            'date_hired'        =>  now(),
            'emp_id'            => str_pad(rand(0,9999999999), 10, '0', STR_PAD_LEFT )
        ];

        $evaluator = [
            'position_id'       => 95,
            'department_id'     => 8,
            'branch_id'         => 126,
            'username'          => 'evaluator',
            'fname'             => 'EVALUATOR',
            'lname'             => 'EVALUATOR',
            'email'             => 'evaluator@smct.com',
            'contact'           => '09'.str_pad(rand(0,999999999), 9, '0', STR_PAD_LEFT ),
            'password'          => 'password',
            'is_active'         => 'active',
            'date_hired'        =>  now(),
            'emp_id'            => str_pad(rand(0,9999999999), 10, '0', STR_PAD_LEFT )
        ];

        $employee = [
            'position_id'       => 8,
            'department_id'     => 8,
            'branch_id'         => 126,
            'username'          => 'employee',
            'fname'             => 'EMPLOYEE',
            'lname'             => 'EMPLOYEE',
            'email'             => 'employee@smct.com',
            'contact'           => '09'.str_pad(rand(0,999999999), 9, '0', STR_PAD_LEFT ),
            'password'          => 'password',
            'is_active'         => 'active',
            'date_hired'        =>  now(),
            'emp_id'            => str_pad(rand(0,9999999999), 10, '0', STR_PAD_LEFT )
        ];

        $role_admin->users()->create($admin);
        $role_employee->users()->create($employee);
        $role_hr_manager->users()->create($hr);
        $role_evaluator->users()->create($evaluator);
    }
}
