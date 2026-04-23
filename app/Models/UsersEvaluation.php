<?php

namespace App\Models;

use App\Enum\EvalReviewType;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class UsersEvaluation extends Model
{

    use HasFactory;

    protected $guarded = [];

    protected $casts = [
        'reviewTypeRegular' => EvalReviewType::class
    ];

    public function employee()
    {
        return $this->belongsTo(User::class, 'employee_id');
    }

    public function evaluator()
    {
        return $this->belongsTo(User::class, 'evaluator_id');
    }

    public function jobKnowledge()
    {
        return $this->hasMany(JobKnowledge::class, 'users_evaluation_id');
    }

    public function adaptability()
    {
        return $this->hasMany(Adaptability::class, 'users_evaluation_id');
    }

    public function qualityOfWorks()
    {
        return $this->hasMany(QualityOfWork::class, 'users_evaluation_id');
    }

    public function teamworks()
    {
        return $this->hasMany(Teamwork::class, 'users_evaluation_id');
    }

    public function reliabilities()
    {
        return $this->hasMany(Reliability::class, 'users_evaluation_id');
    }

    public function ethicals()
    {
        return $this->hasMany(Ethical::class, 'users_evaluation_id');
    }

    public function customerServices()
    {
        return $this->hasMany(CustomerService::class, 'users_evaluation_id');
    }

    public function managerialSkills()
    {
        return $this->hasMany(ManagerialSkills::class, 'users_evaluation_id');
    }

    public function loadRelations()
    {
        $relations = [
            'employee',
            'employee.branches',
            'employee.branch',
            'employee.positions',
            'evaluator',
            'evaluator.branches',
            'evaluator.branch',
            'evaluator.positions',
            'jobKnowledge',
            'adaptability',
            'qualityOfWorks',
            'teamworks',
            'reliabilities',
            'ethicals',
        ];

        if ($this->evaluationType === 'BranchRankNFile' || $this->evaluationType === 'BranchBasic') {
            $relations[] = 'customerServices';
        }

        if ($this->evaluationType === 'HoBasic' || $this->evaluationType === 'BranchBasicAreaManager' || $this->evaluationType === 'BranchBasic') {
            $relations[] = 'managerialSkills';
        }

        $user_eval = $this->load($relations);

        return $user_eval;
    }

    #[Scope]
    public function search($query, $search)
    {
        return
            $query->when(
                $search,
                function ($sub) use ($search) {
                    $sub->where( function($query) use ($search) {
                        $query->whereHas('employee', function ($e) use ($search) {
                            $e->where( function ($q) use ($search){
                                    $q->whereRaw("CONCAT(fname, ' ', lname) LIKE ?", ["%{$search}%"])
                                    ->orWhereRaw("CONCAT(lname, ' ', fname) LIKE ?", ["%{$search}%"]);
                                })
                                ->orWhereAny(['email', 'username'], 'LIKE', "%{$search}%");
                        })
                        ->orWhereHas('evaluator', function ($e) use ($search) {
                            $e->where( function ($q) use ($search){
                                    $q->whereRaw("CONCAT(fname, ' ', lname) LIKE ?", ["%{$search}%"])
                                    ->orWhereRaw("CONCAT(lname, ' ', fname) LIKE ?", ["%{$search}%"]);
                                })
                                ->orWhereAny(['email', 'username'], 'LIKE', "%{$search}%");
                        });
                    });
                }
            );
    }
}
