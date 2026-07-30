<?php

namespace App\Http\Controllers\Api;

use App\Enum\EvalStatus;
use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\UsersEvaluation;
use App\Notifications\EvalNotifications;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;

use function Laravel\Prompts\select;

class UsersEvaluationController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index(Request $request)
    {
        $perPage = $request->input('per_page', 10);
        $search = $request->input('search');
        $status = $request->input('status');
        $quarter = $request->input('quarter');
        $year = $request->input('year');
        $rating = $request->input('rating');
        $branches = [];
        if(!empty($request->input('branch'))) {
            $branches = array_merge(explode(',',$request->input('branch'))) ;
        }

        // $isHr = Auth::user()->hasRole('hr');

        $all_evaluations = UsersEvaluation::query()
            ->with(
                [
                    'employee:id,position_id,branch_id,fname,lname',
                    'employee.branch:id,branch_code,branch_name',
                    'employee.positions:id,label',
                    'evaluator:id,fname,lname,signature',
                ]
            )
            ->select(
                [
                    "id",
                    "employee_id",
                    "evaluator_id",
                    "employee_branch_code",
                    "rating",
                    "status",
                    "reviewTypeProbationary",
                    "reviewTypeRegular",
                    "reviewTypeOthersImprovement",
                    "reviewTypeOthersCustom",
                    "evaluatorApprovedAt",
                    "employeeApprovedAt",
                    "created_at",
                ]
            )
            // ->when($isHr, fn($q) => $q->whereIn('status', [EvalStatus::pending, EvalStatus::completed]))
            ->search($search)
            ->when($status,  fn($q) => $q->where('status', $status))
            ->when($quarter, fn($q) => $q->where(fn($sub) => $sub->where('reviewTypeRegular', $quarter)->orWhere('reviewTypeProbationary', $quarter)))
            ->when($year,
                fn($q)
                =>
                $q->where(
                    fn($r)
                    =>
                    $r->whereYear('coverageTo', $year)->orWhereYear('coverageFrom', $year)
                )
            )
            ->when($rating,  function ($q) use ($rating) {
                match ($rating) {
                    'poor'      => $q->where('rating', '<', 2.5),
                    'low'       => $q->where('rating', '<', 3),
                    'good'      => $q->whereBetween('rating', [3, 3.9]),
                    'excellent' => $q->where('rating', '>=', 4),
                    default     => $q->where('rating', 5),
                };
            })
            ->when(!empty($branches), function ($q) use ($branches) {
                $q->whereHas('employee', function ($sub) use ($branches) {
                    $sub->where(function ($query) use ($branches) {
                        $query->whereHas('branches', function ($q) use ($branches) {
                            $q->whereIn('branches.id', $branches);
                        })
                        ->orWhereHas('branch', function ($q) use ($branches) {
                            $q->whereIn('branches.id', $branches);
                        });
                    });
                });
            })
            ->latest('created_at')
            ->paginate($perPage);

        return response()->json(
            [
                'evaluations' => $all_evaluations,
            ],
            200
        );
    }

    public function getQuarters(User $user)
    {
        $data = UsersEvaluation::where('employee_id', $user->id)
            ->where(function ($q) {
                $q->whereNotNull('reviewTypeProbationary')
                ->orWhereNotNull('reviewTypeRegular');
            })
            ->where(function($q) {
                $q->whereYear('coverageFrom', now()->year)
                ->orWhereYear('coverageTo', now()->year);
            })
            ->get(
                [
                    'reviewTypeProbationary',
                    'reviewTypeRegular'
                ]
            );

        return response()->json(
            [
                'data' => $data,
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
     * Display the specified resource.
     */
    public function show(UsersEvaluation $usersEvaluation)
    {
        return response()->json(
            [
                'user_eval' => $usersEvaluation->loadRelations(),
            ],
            200
        );
    }

    public function getMyEvalAuthEmployee(Request $request)
    {
        $perPage = $request->input('per_page', 10);
        $search = $request->input('search');
        $status = $request->input('status');
        $quarter = $request->input('quarter');
        $year = $request->input('year');

        $user = Auth::user();
        $user_eval = UsersEvaluation::query()
            ->with(
                [
                    // 'employee:id,position_id,branch_id,fname,lname,emp_id,contact,date_hired,signature',
                    // 'employee.branch:id,branch_code,branch_name',
                    // 'employee.positions:id,label',
                    'evaluator:id,fname,lname',
                    // 'approver1:id,fname,lname,signature',
                    // 'approver2:id,fname,lname,signature',
                    // 'rejectedBy:id,fname,lname',
                    // 'jobKnowledge',
                    // 'adaptability',
                    // 'qualityOfWorks',
                    // 'teamworks',
                    // 'reliabilities',
                    // 'ethicals',
                    // 'customerServices'
                ]
            )
            ->select(
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
            ->whereIn('status', [EvalStatus::pending, EvalStatus::completed])
            ->search($search)
            ->when($status, fn($q) => $q->where('status', $status))
            ->when(
                $quarter,
                fn($q) => $q->where(function ($subq) use ($quarter) {
                    match ($quarter) {
                        'Others'    => $subq->whereNot('reviewTypeOthersImprovement', 0)->orWhereNotNull('reviewTypeOthersCustom'),
                        default     => $subq->where('reviewTypeProbationary', $quarter)->orWhere('reviewTypeRegular', $quarter),
                    };
                })
            )
            ->when($year, fn($q) => $q->where( fn($r)=> $r->whereYear('coverageFrom', $year)->orWhereYear('coverageTo', $year)))
            ->latest('created_at')
            ->paginate($perPage);

        $years = UsersEvaluation::selectRaw('YEAR(created_at) as year')->where('employee_id', $user->id)->groupBy('year')->get();

        return response()->json(
            [
                'myEval_as_Employee' => $user_eval,
                'years' => $years,
            ],
            200
        );
    }

    public function getEvalAuthEvaluator(Request $request)
    {
        $perPage = $request->input('per_page', 10);
        $search = $request->input('search');
        $status = $request->input('status');
        $quarter = $request->input('quarter');
        $year = $request->input('year');

        $user = Auth::user();

        $user_eval = UsersEvaluation::query()
            ->with(
                [
                    'employee:id,branch_id,fname,lname',
                    'employee.branch:id,branch_code,branch_name',
                    'evaluator:id,fname,lname',
                    'approver1:id,fname,lname,signature',
                    'approver2:id,fname,lname,signature',
                    'rejectedBy:id,fname,lname',
                    // 'jobKnowledge',
                    // 'adaptability',
                    // 'qualityOfWorks',
                    // 'teamworks',
                    // 'reliabilities',
                    // 'ethicals',
                    // 'customerServices'
                ]
            )
            ->select(
                [
                    "id",
                    "employee_id",
                    "evaluator_id",
                    "approver1_id",
                    "approver2_id",
                    "rejected_by_id",
                    "employee_branch_code",
                    "rating",
                    "status",
                    "noteIfRejected",
                    "reviewTypeProbationary",
                    "reviewTypeRegular",
                    "reviewTypeOthersImprovement",
                    "reviewTypeOthersCustom",
                    "evaluatorApprovedAt",
                    "employeeApprovedAt",
                    "created_at",
                ]
            )
            // ->where(
            //     fn($q)
            //     =>
            //     $q->where(
            //         fn($q) => $q->where('status', "pending_approval_1")->where('approver1_id', $user->id)
            //     )->orWhere(
            //         fn($q) => $q->where('status', "pending_approval_2")->where('approver2_id', $user->id)
            //     )
            // )
            ->whereIn('status',[EvalStatus::pending, EvalStatus::completed])
            ->where('evaluator_id', $user->id)
            ->search($search)
            ->when($status, fn($q) => $q->where('status', $status))
            ->when(
                $quarter,
                fn($q) => $q->where(function ($subq) use ($quarter) {
                    match ($quarter) {
                        'Others'    => $subq->whereNot('reviewTypeOthersImprovement', false)->orWhereNotNull('reviewTypeOthersCustom'),
                        default     => $subq->where('reviewTypeProbationary', $quarter)->orWhere('reviewTypeRegular', $quarter),
                    };
                })
            )
            ->when($year, fn($q) => $q->where( fn($r) => $r->whereYear('coverageFrom', $year)->orWhereYear('coverageTo', $year)))
            ->latest('created_at')
            ->paginate($perPage);

        return response()->json(
            [
                'myEval_as_Evaluator'       => $user_eval,
                'myEval_as_Evaluator_count' => $user_eval->total(),
            ],
            200
        );
    }

    public function getPendingApprovalEvaluations(Request $request)
    {
        $perPage = $request->input('per_page', 10);
        $search = $request->input('search');
        $status = $request->input('status');
        $quarter = $request->input('quarter');
        $year = $request->input('year');

        $user = Auth::user();

        $user_eval = UsersEvaluation::query()
            ->with(
                [
                    'employee:id,branch_id,fname,lname',
                    'employee.branch:id,branch_code,branch_name',
                    'evaluator:id,fname,lname',
                    'approver1:id,fname,lname,signature',
                    'approver2:id,fname,lname,signature',
                    'rejectedBy:id,fname,lname',
                    // 'jobKnowledge',
                    // 'adaptability',
                    // 'qualityOfWorks',
                    // 'teamworks',
                    // 'reliabilities',
                    // 'ethicals',
                    // 'customerServices'
                ]
            )
            ->select(
                [
                    "id",
                    "employee_id",
                    "evaluator_id",
                    "approver1_id",
                    "approver2_id",
                    "rejected_by_id",
                    "employee_branch_code",
                    "rating",
                    "status",
                    "noteIfRejected",
                    "reviewTypeProbationary",
                    "reviewTypeRegular",
                    "reviewTypeOthersImprovement",
                    "reviewTypeOthersCustom",
                    "evaluatorApprovedAt",
                    "employeeApprovedAt",
                    "created_at",
                ]
            )
            ->where(
                fn($q)
                =>
                $q->where(
                    fn($q) => $q->where('status', "pending_approval_1")->where('approver1_id', $user->id)
                )->orWhere(
                    fn($q) => $q->where('status', "pending_approval_2")->where('approver2_id', $user->id)
                )->orWhere(
                    fn($q) => $q->where('evaluator_id', $user->id)
                )
            )
            ->whereIn('status',[EvalStatus::rejected, EvalStatus::pending_approval_1, EvalStatus::pending_approval_2])
            ->search($search)
            ->when($status, fn($q) => $q->where('status', $status))
            ->when(
                $quarter,
                fn($q) => $q->where(function ($subq) use ($quarter) {
                    match ($quarter) {
                        'Others'    => $subq->whereNot('reviewTypeOthersImprovement', false)->orWhereNotNull('reviewTypeOthersCustom'),
                        default     => $subq->where('reviewTypeProbationary', $quarter)->orWhere('reviewTypeRegular', $quarter),
                    };
                })
            )
            ->when($year, fn($q) => $q->where( fn($r) => $r->whereYear('coverageFrom', $year)->orWhereYear('coverageTo', $year)))
            ->latest('created_at')
            ->paginate($perPage);

        return response()->json(
            [
                'myEval_as_Evaluator'       => $user_eval,
                'myEval_as_Evaluator_count' => $user_eval->total(),
            ],
            200
        );
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
    public function approvedByEmployee(UsersEvaluation $usersEvaluation)
    {
        $usersEvaluation->update(
            [
                'status'                => 'completed',
                'employeeApprovedAt'    => now(),
            ]
        );

        $evaluator = User::findOrFail($usersEvaluation->evaluator_id);
        $auth_user_employee = Auth::user();

        $evaluator->notify(new EvalNotifications('Your submitted evaluation for ' . $auth_user_employee->fname . ' ' . $auth_user_employee->lname . ' has been successfully approved.'));

        $notificationData = new EvalNotifications('An evaluation submitted by ' . $evaluator->fname . ' ' . $evaluator->lname . ' for ' . $auth_user_employee->fname . ' ' . $auth_user_employee->lname . ' has been approved ');

        User::with('roles')
            ->whereHas('roles', fn($q) => $q->where('name', 'hr')->orWhere('name', 'admin'))
            ->chunk(100, function ($hrs) use ($notificationData)
                {
                    Notification::send($hrs, $notificationData);
                }
            );

        return response()->json(
            [
                'message'   => 'Evaluation approved by employee successfully',
                'data'      => $usersEvaluation->loadRelations(),
            ],
            200
        );
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(UsersEvaluation $usersEvaluation)
    {
        $authUser = Auth::user();
        if($authUser->roles()->where('name', 'admin')->exists() || $authUser->roles()->where('name', 'hr')->exists()){
            $usersEvaluation->delete();

            return response()->json(
                [
                    'message' => 'Deleted Successfully',
                ],
                200
            );
        }

        return response()->json(
            [
                'message'       =>  "This evaluation can’t be deleted because both parties have approved it. Please refresh to view the latest updates."
            ]
            ,400
        );
    }

    public function approveEvaluation(UsersEvaluation $usersEvaluation)
    {
        if(Auth::id() == $usersEvaluation->approver1_id)
        {
            if(empty($usersEvaluation->approver2_id))
            {
                $usersEvaluation->update(
                    [
                        'noteIfRejected'                => null,
                        'rejected_by_id'                => null,
                        'firstApproverApprovedAt'       => now(),
                        'status'                        => EvalStatus::pending
                    ]
                );

                return response()->json(
                    [
                        'message'       =>  'Approval Successfully'
                    ]
                    ,200
                );
            }

            $usersEvaluation->update(
                [
                    'noteIfRejected'                => null,
                    'rejected_by_id'                => null,
                    'firstApproverApprovedAt'       => now(),
                    'status'                        => EvalStatus::pending_approval_2
                ]
            );

            return response()->json(
                [
                    'message'       =>  'Approval Successfully'
                ]
                ,200
            );
        }


        if(Auth::id() == $usersEvaluation->approver2_id )
        {
            $usersEvaluation->update(
                [
                    'noteIfRejected'                => null,
                    'rejected_by_id'                => null,
                    'secondApproverApprovedAt'      => now(),
                    'status'                        => EvalStatus::pending
                ]
            );

            return response()->json(
                [
                    'message'       =>  'Approval Successfully'
                ]
                ,200
            );
        }

        return response()->json(
            [
                'message'       =>  'Approval Unsuccessfully'
            ]
            ,400
        );
    }

    public function rejectDraftEvaluation(UsersEvaluation $usersEvaluation,Request $request)
    {
        $validated = $request->validate(
            [
                'note'      =>  ['required','string','max:20']
            ]
        );

        $usersEvaluation->update(
            [
                'status'            =>  EvalStatus::rejected,
                'noteIfRejected'    =>  $validated['note'],
                'rejected_by_id'    =>  Auth::id()
            ]
        );

        return response()->json(
            [
                'message'   =>  'Evaluation reject Successfully'
            ]
            ,201
        );
    }

    public function getAllYears()
    {
        $years = UsersEvaluation::select(DB::raw('YEAR(created_at) as year'))->distinct()->orderBy('year', 'DESC')->get();

        return response()->json(
            [
                'years' => $years,
            ],
            200
        );
    }

}
