<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\UsersEvaluation;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;


class EmployeeDashboardController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $user = Auth::user();

        $user_eval = UsersEvaluation::select(
                                [
                                    "id",
                                    "evaluator_id",
                                    "rating",
                                    "status",
                                    "reviewTypeProbationary",
                                    "reviewTypeRegular",
                                    "reviewTypeOthersImprovement",
                                    "reviewTypeOthersCustom",
                                    "created_at",
                                ]
                            )
                            ->where('employee_id', $user->id)
                            ->whereIn('status', ['pending', 'completed'])
                            ->get();

        $total_evaluations = UsersEvaluation::where('employee_id', $user->id)->whereIn('status', ['pending', 'completed'])->count() ?: 0;
        $sum_ratings = UsersEvaluation::where('employee_id', $user->id)->whereIn('status', ['pending', 'completed'])->whereNotNull("rating")->sum('rating') ?: 0;
        $average = empty(!$total_evaluations) ? round($sum_ratings / $total_evaluations, 2) : 0;
        $recent_evaluation_rating = UsersEvaluation::where('employee_id', $user->id)
                ->whereIn('status', ['pending', 'completed'])
                ->latest('created_at')
                ->select('id', 'rating')
                ->first();

        return response()->json(
            [
                'total_evaluations'     =>  $total_evaluations,
                'average'               =>  $average,
                'recent_evaluation'     =>  $recent_evaluation_rating,
                'user_eval'             =>  $user_eval,
            ],
            200
        );
    }

    public function index2(User $user)
    {
        $user_eval = UsersEvaluation::select(
                                [
                                    "id",
                                    "evaluator_id",
                                    "rating",
                                    "status",
                                    "reviewTypeProbationary",
                                    "reviewTypeRegular",
                                    "reviewTypeOthersImprovement",
                                    "reviewTypeOthersCustom",
                                    "created_at",
                                ]
                            )
                            ->where('employee_id', $user->id)
                            ->whereIn('status', ['pending', 'completed'])
                            ->get();

        $total_evaluations = UsersEvaluation::where('employee_id', $user->id)->whereIn('status', ['pending', 'completed'])->count() ?: 0;
        $sum_ratings = UsersEvaluation::where('employee_id', $user->id)->whereIn('status', ['pending', 'completed'])->whereNotNull("rating")->sum('rating') ?: 0;
        $average = empty(!$total_evaluations) ? round($sum_ratings / $total_evaluations, 2) : 0;
        $recent_evaluation = UsersEvaluation::where('employee_id', $user->id)
                                ->whereIn('status', ['pending', 'completed'])
                                ->latest('created_at')
                                ->select('id', 'rating')
                                ->first();

        $highest_rating = UsersEvaluation::where('employee_id', $user->id)
                            ->whereIn('status', ['pending', 'completed'])
                            ->max('rating');

        return response()->json(
            [
                'highest_rating'        =>  $highest_rating,
                'total_evaluations'     =>  $total_evaluations,
                'average'               =>  $average,
                'recent_evaluation'     =>  $recent_evaluation,
                'user_eval'             =>  $user_eval,
            ],
            200
        );
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        //
    }

    /**
     * Display the specified resource.
     */
    public function show(string $id)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(string $id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {
        //
    }
}
