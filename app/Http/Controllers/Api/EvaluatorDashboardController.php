<?php

namespace App\Http\Controllers\Api;

use App\Models\UsersEvaluation;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class EvaluatorDashboardController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index(Request $request)
    {
        $user = Auth::user();

        $total_evaluations = UsersEvaluation::where('evaluator_id', $user->id)->whereNotNull('rating')->count() ?: 0;
        $sum_ratings = UsersEvaluation::where('evaluator_id', $user->id)->whereNotNull('rating')->sum('rating') ?: 0;
        $team_average = !empty($total_evaluations) ? ($sum_ratings / $total_evaluations) : 0;

        // Eval approvals
        $total_pending = UsersEvaluation::where('evaluator_id', $user->id)->where('status', 'pending')->whereNotNull('rating')->count() ?: 0;
        $total_approved = UsersEvaluation::where('evaluator_id', $user->id)->where('status', 'completed')->whereNotNull('rating')->count() ?: 0;

        $page = $request->input('per_page', 10);
        $search = $request->input('search');
        $status = $request->input('status');
        $quarter = $request->input('quarter');
        $year = $request->input('year');

        $user_eval = UsersEvaluation::with(
            [
                'employee',
                'evaluator',
                'jobKnowledge',
                'adaptability',
                'qualityOfWorks',
                'teamworks',
                'reliabilities',
                'ethicals',
                'customerServices'
            ])
            ->where('evaluator_id', $user->id)
            ->search($search)
            ->when($status,  fn($q)  =>  $q->where('status', $status))
            ->when($quarter, fn($q)  =>  $q->where('quarter_of_submission_id', $quarter))
            ->when($year,    fn($q)  =>  $q->whereYear('created_at', $year))
            ->latest('updated_at')
            ->paginate($page);

        return response()->json(
            [
                'total_evaluations'           => $total_evaluations,
                'team_average'                => $team_average,
                'total_pending'               => $total_pending,
                'total_approved'              => $total_approved,
                'myEval_as_Evaluator'         => $user_eval
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
