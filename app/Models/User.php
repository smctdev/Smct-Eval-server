<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;

use Illuminate\Database\Eloquent\Attributes\Scope;
use Spatie\Permission\Traits\HasRoles;

/**
 * @method \Illuminate\Support\Collection getRoleNames()
 * @method void assignRole(...$roles)
 */

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

class User extends Authenticatable
{
    use HasFactory, HasRoles, Notifiable;
    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $guarded = [];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    protected $appends = [
        'full_name'
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }

    public function branches()
    {
        return $this->belongsToMany(Branch::class, 'branch_user');
    }

    public function departments()
    {
        return $this->belongsTo(Department::class, 'department_id');
    }

    public function positions()
    {
        return $this->belongsTo(Position::class, 'position_id');
    }

    public function evaluations()
    {
        return $this->hasMany(UsersEvaluation::class, 'employee_id');
    }

    public function doesEvaluated()
    {
        return $this->hasMany(UsersEvaluation::class, 'evaluator_id');
    }

    public function memos()
    {
        return $this->hasMany(MemorandumViolation::class, 'evaluator_id');
    }

    public function getFullNameAttribute()
    {
        return $this->fname . " " . $this->lname;
    }

    #[Scope]
    public function search($query, $term)
    {
        return $query
            ->when(
                $term,
                fn($filter)
                =>
                $filter->where(
                    fn($user)
                    =>
                    $user->whereRaw('CONCAT(fname, " ", lname) LIKE ?', ["%{$term}%"])
                        ->orWhereRaw('CONCAT(lname, " ", fname) LIKE ?', ["%{$term}%"])
                        ->orWhereLike('email', "%{$term}%")
                        ->orWhereLike('username', "%{$term}%")
                )
            );
    }

    public function branch()
    {
        return $this->belongsTo(Branch::class);
    }
}
