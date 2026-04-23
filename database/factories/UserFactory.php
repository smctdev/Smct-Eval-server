<?php

namespace Database\Factories;

use App\Models\Branch;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Hash;
use App\Models\Position;
use App\Models\Department;
use App\Models\SubSection;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\User>
 */
class UserFactory extends Factory
{
    /**
     * The current password being used by the factory.
     */

    protected static ?string $password;

    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        $branch_id = Branch::all()->random()->id;
        $department_id = $branch_id === 126 ? Department::all()->random()->id : null;

        return [
            'branch_id'     => $branch_id ,
            'position_id'   => Position::all()->random()->id,
            'department_id' => $department_id,
            'username'      => $this->faker->unique()->userName(),
            'date_hired'    => $this->faker->dateTime(),
            'fname'         => $this->faker->firstName(),
            'lname'         => $this->faker->lastName(),
            'email'         => $this->faker->unique()->safeEmail(),
            'contact'       => '09'.str_pad(rand(0,999999999), 9, '0' , STR_PAD_LEFT),
            'emp_id'        => str_pad(rand(0,9999999999), 10, '0' , STR_PAD_LEFT),
            'password'      => Hash::make('password'),
            'is_active'     => fake()->randomElement(["pending", "active"]),
            'avatar'        => null,
        ];
    }


    /**
     * Indicate that the model's email address should be unverified.
     */
    public function unverified(): static
    {
        return $this->state(fn(array $attributes) => [
            'email_verified_at' => null,
        ]);
    }
}
