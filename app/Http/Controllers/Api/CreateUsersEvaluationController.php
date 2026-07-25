<?php

namespace App\Http\Controllers\Api;

use App\Enum\EvalStatus;
use App\Enum\QuarterDateRange;
use App\Http\Controllers\Controller;
use App\Http\Requests\create\BranchBasic;
use App\Http\Requests\create\BranchBasicAreaManager;
use App\Http\Requests\create\BranchRankNFile;
use App\Http\Requests\create\HoBasic;
use App\Http\Requests\create\HoRankNFile;
use App\Models\User;
use App\Models\UsersEvaluation;
use App\Notifications\EvalNotifications;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;

class CreateUsersEvaluationController extends Controller
{
    //
     public function getApprovers(int $id)
    {
        return DB::table('assign_approvers')->where('evaluator_id', $id)->get();
    }

    public function BranchRankNFile(BranchRankNFile $validated, User $user)
    {
        try {
            DB::transaction(function () use ($validated, $user) {

                $auth_user_evaluator = Auth::user();

                $status = '';
                $approver1 = null;
                $approver2 = null;
                $approverModel = $this->getApprovers($auth_user_evaluator->id);

                if(!$approverModel || $approverModel->isEmpty()){
                    $status = EvalStatus::pending;
                }else{
                    $status = EvalStatus::pending_approval_1;
                    $approver1 = $approverModel->firstWhere('sequence', 1)?->approver_id;
                    $approver2 = $approverModel->firstWhere('sequence', 2)?->approver_id;
                }

                $evalDateFrom = $validated['coverageFrom'];
                $evalDateTo = $validated['coverageTo'];

                if(!empty($validated['reviewTypeRegular']))
                {
                    [$evalDateFrom, $evalDateTo] = match($validated['reviewTypeRegular'])
                    {
                            "Q1"    =>  QuarterDateRange::Q1->range(),
                            "Q2"    =>  QuarterDateRange::Q2->range(),
                            "Q3"    =>  QuarterDateRange::Q3->range(),
                            "Q4"    =>  QuarterDateRange::Q4->range(),
                    };
                }

                $submission = UsersEvaluation::create(
                    [
                        'employee_id'                   => $user->id,
                        'evaluator_id'                  => $auth_user_evaluator->id,
                        'approver1_id'                  => $approver1,
                        'approver2_id'                  => $approver2,
                        'evaluationType'                => 'BranchRankNFile',
                        'employee_branch_code'          => $user->branch?->branch_code,
                        'rating'                        => $validated['rating'],
                        'percentage'                    => $validated['performanceScore'],
                        'coverageFrom'                  => $evalDateFrom,
                        'coverageTo'                    => $evalDateTo,
                        'reviewTypeProbationary'        => $validated['reviewTypeProbationary'] ?: null,
                        'reviewTypeRegular'             => $validated['reviewTypeRegular'] ?: null,
                        'reviewTypeOthersImprovement'   => $validated['reviewTypeOthersImprovement'] ?: null,
                        'reviewTypeOthersCustom'        => $validated['reviewTypeOthersCustom'] ?: null,
                        'priorityArea1'                 => $validated['priorityArea1'] ?: null,
                        'priorityArea2'                 => $validated['priorityArea2'] ?: null,
                        'priorityArea3'                 => $validated['priorityArea3'] ?: null,
                        'remarks'                       => $validated['remarks'] ?: null,
                        'evaluatorApprovedAt'           => now(),
                        'status'                        => $status
                    ]
                );

                for ($i = 1; $i <= 3; $i++) {
                    $submission->jobKnowledge()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['jobKnowledgeScore' . $i],
                            'comment'               => $validated['jobKnowledgeComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 5; $i++) {
                    $submission->qualityOfWorks()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['qualityOfWorkScore' . $i],
                            'comment'               => $validated['qualityOfWorkComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 3; $i++) {
                    $submission->adaptability()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['adaptabilityScore' . $i],
                            'comment'               => $validated['adaptabilityComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 3; $i++) {
                    $submission->teamworks()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['teamworkScore' . $i],
                            'comment'               => $validated['teamworkComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 4; $i++) {
                    $submission->reliabilities()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['reliabilityScore' . $i],
                            'comment'               => $validated['reliabilityComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 4; $i++) {
                    $submission->ethicals()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['ethicalScore' . $i],
                            'explanation'           => $validated['ethicalExplanation' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 5; $i++) {
                    $submission->customerServices()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['customerServiceScore' . $i],
                            'explanation'           => $validated['customerServiceExplanation' . $i] ?: null,
                        ]
                    );
                }
                //notification for employee
                $user->notify(new EvalNotifications('An evaluation submitted by ' . $auth_user_evaluator->fname . ' ' . $auth_user_evaluator->lname . ' is awaiting your sign.'));

                //notification for admin and hr
                $notificationData = new EvalNotifications('A new evaluation submitted for ' . $user->fname . ' ' . $user->lname . ' was submitted by ' . $auth_user_evaluator->fname . ' ' . $auth_user_evaluator->lname);

                User::with('roles')
                    ->whereHas('roles', fn($q) => $q->where('name', 'hr')->orWhere('name', 'admin'))
                    ->chunk(100, function ($hrs) use ($notificationData)
                        {
                            Notification::send($hrs, $notificationData);
                        }
                    );

            });

            return response()->json(
                [
                    'message' => 'Submitted successfully.',
                ],
                201
            );

        } catch (\Throwable $e) {
            return response()->json(
                [
                    'message' => $e->getMessage(),
                ],
                500
            );
        }
    }

    public function BranchBasicAreaManager(BranchBasicAreaManager $validated, User $user)
    {
        try {
            DB::transaction(function () use ($validated, $user) {

                $auth_user_evaluator = Auth::user();

                $status = '';
                $approver1 = null;
                $approver2 = null;
                $approverModel = $this->getApprovers($auth_user_evaluator->id);

                if(!$approverModel || $approverModel->isEmpty()){
                    $status = EvalStatus::pending;
                }else{
                    $status = EvalStatus::pending_approval_1;
                    $approver1 = $approverModel->firstWhere('sequence', 1)?->approver_id;
                    $approver2 = $approverModel->firstWhere('sequence', 2)?->approver_id;
                }

                $evalDateFrom = $validated['coverageFrom'];
                $evalDateTo = $validated['coverageTo'];

                if(!empty($validated['reviewTypeRegular']))
                {
                    [$evalDateFrom, $evalDateTo] = match($validated['reviewTypeRegular'])
                    {
                            "Q1"    =>  QuarterDateRange::Q1->range(),
                            "Q2"    =>  QuarterDateRange::Q2->range(),
                            "Q3"    =>  QuarterDateRange::Q3->range(),
                            "Q4"    =>  QuarterDateRange::Q4->range(),
                    };
                }

                $submission = UsersEvaluation::create(
                    [
                        'employee_id'                   => $user->id,
                        'evaluator_id'                  => $auth_user_evaluator->id,
                        'approver1_id'                  => $approver1,
                        'approver2_id'                  => $approver2,
                        'evaluationType'                => 'BranchBasicAreaManager',
                        'employee_branch_code'          => $user->branch?->branch_code,
                        'rating'                        => $validated['rating'],
                        'percentage'                    => $validated['performanceScore'],
                        'coverageFrom'                  => $evalDateFrom,
                        'coverageTo'                    => $evalDateTo,
                        'reviewTypeProbationary'        => $validated['reviewTypeProbationary'] ?: null,
                        'reviewTypeRegular'             => $validated['reviewTypeRegular'] ?: null,
                        'reviewTypeOthersImprovement'   => $validated['reviewTypeOthersImprovement'] ?: null,
                        'reviewTypeOthersCustom'        => $validated['reviewTypeOthersCustom'] ?: null,
                        'priorityArea1'                 => $validated['priorityArea1'] ?: null,
                        'priorityArea2'                 => $validated['priorityArea2'] ?: null,
                        'priorityArea3'                 => $validated['priorityArea3'] ?: null,
                        'remarks'                       => $validated['remarks'] ?: null,
                        'evaluatorApprovedAt'           => now(),
                        'status'                        => $status
                    ]
                );

                for ($i = 1; $i <= 3; $i++) {
                    $submission->jobKnowledge()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['jobKnowledgeScore' . $i],
                            'comment'               => $validated['jobKnowledgeComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 12; $i++) {
                    $submission->qualityOfWorks()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['qualityOfWorkScore' . $i],
                            'comment'               => $validated['qualityOfWorkComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 3; $i++) {
                    $submission->adaptability()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['adaptabilityScore' . $i],
                            'comment'               => $validated['adaptabilityComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 3; $i++) {
                    $submission->teamworks()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['teamworkScore' . $i],
                            'comment'               => $validated['teamworkComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 4; $i++) {
                    $submission->reliabilities()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['reliabilityScore' . $i],
                            'comment'               => $validated['reliabilityComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 4; $i++) {
                    $submission->ethicals()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['ethicalScore' . $i],
                            'explanation'           => $validated['ethicalExplanation' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 6; $i++) {
                    $submission->managerialSkills()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['managerialSkillsScore' . $i],
                            'explanation'           => $validated['managerialSkillsExplanation' . $i] ?: null,
                        ]
                    );
                }
                //notification for employee
                $user->notify(new EvalNotifications('An evaluation submitted by ' . $auth_user_evaluator->fname . ' ' . $auth_user_evaluator->lname . ' is awaiting your sign.'));

                //notification for admin and hr
                $notificationData = new EvalNotifications('A new evaluation submitted for ' . $user->fname . ' ' . $user->lname . ' was submitted by ' . $auth_user_evaluator->fname . ' ' . $auth_user_evaluator->lname);

                User::with('roles')
                    ->whereHas('roles', fn($q) => $q->where('name', 'hr')->orWhere('name', 'admin'))
                    ->chunk(100, function ($hrs) use ($notificationData)
                        {
                        Notification::send($hrs, $notificationData);
                        }
                    );

            });

            return response()->json(
                [
                    'message' => 'Submitted successfully.',
                ]
                , 201
            );

        } catch (\Throwable $e) {
            return response()->json(
                [
                    'message' => $e->getMessage(),
                ],
                500
            );
        }
    }

    public function BranchBasic(BranchBasic $validated, User $user)
    {
        try {
            DB::transaction(function () use ($validated, $user) {

                $auth_user_evaluator = Auth::user();

                $status = '';
                $approver1 = null;
                $approver2 = null;
                $approverModel = $this->getApprovers($auth_user_evaluator->id);

                if(!$approverModel || $approverModel->isEmpty()){
                    $status = EvalStatus::pending;
                }else{
                    $status = EvalStatus::pending_approval_1;
                    $approver1 = $approverModel->firstWhere('sequence', 1)?->approver_id;
                    $approver2 = $approverModel->firstWhere('sequence', 2)?->approver_id;
                }


                $evalDateFrom = $validated['coverageFrom'];
                $evalDateTo = $validated['coverageTo'];

                if(!empty($validated['reviewTypeRegular']))
                {
                    [$evalDateFrom, $evalDateTo] = match($validated['reviewTypeRegular'])
                    {
                            "Q1"    =>  QuarterDateRange::Q1->range(),
                            "Q2"    =>  QuarterDateRange::Q2->range(),
                            "Q3"    =>  QuarterDateRange::Q3->range(),
                            "Q4"    =>  QuarterDateRange::Q4->range(),
                    };
                }

                $submission = UsersEvaluation::create(
                    [
                        'employee_id'                   => $user->id,
                        'evaluator_id'                  => $auth_user_evaluator->id,
                        'approver1_id'                  => $approver1,
                        'approver2_id'                  => $approver2,
                        'evaluationType'                => 'BranchBasic',
                        'employee_branch_code'          => $user->branch?->branch_code,
                        'rating'                        => $validated['rating'],
                        'percentage'                    => $validated['performanceScore'],
                        'coverageFrom'                  => $evalDateFrom,
                        'coverageTo'                    => $evalDateTo,
                        'reviewTypeProbationary'        => $validated['reviewTypeProbationary'] ?: null,
                        'reviewTypeRegular'             => $validated['reviewTypeRegular'] ?: null,
                        'reviewTypeOthersImprovement'   => $validated['reviewTypeOthersImprovement'] ?: null,
                        'reviewTypeOthersCustom'        => $validated['reviewTypeOthersCustom'] ?: null,
                        'priorityArea1'                 => $validated['priorityArea1'] ?: null,
                        'priorityArea2'                 => $validated['priorityArea2'] ?: null,
                        'priorityArea3'                 => $validated['priorityArea3'] ?: null,
                        'remarks'                       => $validated['remarks'] ?: null,
                        'evaluatorApprovedAt'           => now(),
                        'status'                        => $status
                    ]
                );

                for ($i = 1; $i <= 3; $i++) {
                    $submission->jobKnowledge()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['jobKnowledgeScore' . $i],
                            'comment'               => $validated['jobKnowledgeComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 12; $i++) {
                    $submission->qualityOfWorks()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['qualityOfWorkScore' . $i],
                            'comment'               => $validated['qualityOfWorkComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 3; $i++) {
                    $submission->adaptability()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['adaptabilityScore' . $i],
                            'comment'               => $validated['adaptabilityComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 3; $i++) {
                    $submission->teamworks()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['teamworkScore' . $i],
                            'comment'               => $validated['teamworkComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 4; $i++) {
                    $submission->reliabilities()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['reliabilityScore' . $i],
                            'comment'               => $validated['reliabilityComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 4; $i++) {
                    $submission->ethicals()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['ethicalScore' . $i],
                            'explanation'           => $validated['ethicalExplanation' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 5; $i++) {
                    $submission->customerServices()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['customerServiceScore' . $i],
                            'explanation'           => $validated['customerServiceExplanation' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 6; $i++) {
                    $submission->managerialSkills()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['managerialSkillsScore' . $i],
                            'explanation'           => $validated['managerialSkillsExplanation' . $i] ?: null,
                        ]
                    );
                }
                //notification for employee
                $user->notify(new EvalNotifications('An evaluation submitted by ' . $auth_user_evaluator->fname . ' ' . $auth_user_evaluator->lname . ' is awaiting your sign.'));

                //notification for admin and hr
                $notificationData = new EvalNotifications('A new evaluation submitted for ' . $user->fname . ' ' . $user->lname . ' was submitted by ' . $auth_user_evaluator->fname . ' ' . $auth_user_evaluator->lname);

                User::with('roles')
                    ->whereHas('roles',
                        fn($q)
                        =>
                        $q->where('name', 'hr')
                        ->orWhere('name', 'admin')
                    )
                    ->chunk(100, function ($hrs) use ($notificationData)
                        {
                            Notification::send($hrs, $notificationData);
                        }
                    );
            });

            return response()->json(
                [
                    'message' => 'Submitted successfully.',
                ]
                ,201
            );

        } catch (\Throwable $e) {
            return response()->json(
                [
                    'message' => $e->getMessage(),
                ],
                500
            );
        }
    }

    public function HoRankNFile(HoRankNFile $validated, User $user)
    {
        try {
            DB::transaction(function () use ($validated, $user) {

                $auth_user_evaluator = Auth::user();

                $status = '';
                $approver1 = null;
                $approver2 = null;
                $approverModel = $this->getApprovers($auth_user_evaluator->id);

                if(!$approverModel || $approverModel->isEmpty()){
                    $status = EvalStatus::pending;
                }else{
                    $status = EvalStatus::pending_approval_1;
                    $approver1 = $approverModel->firstWhere('sequence', 1)?->approver_id;
                    $approver2 = $approverModel->firstWhere('sequence', 2)?->approver_id;
                }

                $evalDateFrom = $validated['coverageFrom'];
                $evalDateTo = $validated['coverageTo'];

                if(!empty($validated['reviewTypeRegular']))
                {
                    [$evalDateFrom, $evalDateTo] = match($validated['reviewTypeRegular'])
                    {
                            "Q1"    =>  QuarterDateRange::Q1->range(),
                            "Q2"    =>  QuarterDateRange::Q2->range(),
                            "Q3"    =>  QuarterDateRange::Q3->range(),
                            "Q4"    =>  QuarterDateRange::Q4->range(),
                    };
                }

                $submission = UsersEvaluation::create(
                    [
                        'employee_id'                   => $user->id,
                        'evaluator_id'                  => $auth_user_evaluator->id,
                        'approver1_id'                  => $approver1,
                        'approver2_id'                  => $approver2,
                        'evaluationType'                => 'HoRankNFile',
                        'employee_branch_code'          => $user->branch?->branch_code,
                        'rating'                        => $validated['rating'],
                        'percentage'                    => $validated['performanceScore'],
                        'coverageFrom'                  => $evalDateFrom,
                        'coverageTo'                    => $evalDateTo,
                        'reviewTypeProbationary'        => $validated['reviewTypeProbationary'] ?: null,
                        'reviewTypeRegular'             => $validated['reviewTypeRegular'] ?: null,
                        'reviewTypeOthersImprovement'   => $validated['reviewTypeOthersImprovement'] ?: null,
                        'reviewTypeOthersCustom'        => $validated['reviewTypeOthersCustom'] ?: null,
                        'priorityArea1'                 => $validated['priorityArea1'] ?: null,
                        'priorityArea2'                 => $validated['priorityArea2'] ?: null,
                        'priorityArea3'                 => $validated['priorityArea3'] ?: null,
                        'remarks'                       => $validated['remarks'] ?: null,
                        'evaluatorApprovedAt'           => now(),
                        'status'                        => $status
                    ]
                );

                for ($i = 1; $i <= 3; $i++) {
                    $submission->jobKnowledge()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['jobKnowledgeScore' . $i],
                            'comment'               => $validated['jobKnowledgeComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 4; $i++) {
                    $submission->qualityOfWorks()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['qualityOfWorkScore' . $i],
                            'comment'               => $validated['qualityOfWorkComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 3; $i++) {
                    $submission->adaptability()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['adaptabilityScore' . $i],
                            'comment'               => $validated['adaptabilityComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 3; $i++) {
                    $submission->teamworks()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['teamworkScore' . $i],
                            'comment'               => $validated['teamworkComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 4; $i++) {
                    $submission->reliabilities()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['reliabilityScore' . $i],
                            'comment'               => $validated['reliabilityComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 4; $i++) {
                    $submission->ethicals()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['ethicalScore' . $i],
                            'explanation'           => $validated['ethicalExplanation' . $i] ?: null,
                        ]
                    );
                }

                //notification for employee
                $user->notify(new EvalNotifications('An evaluation submitted by ' . $auth_user_evaluator->fname . ' ' . $auth_user_evaluator->lname . ' is awaiting your sign.'));

                //notification for admin and hr
                $notificationData = new EvalNotifications('A new evaluation submitted for ' . $user->fname . ' ' . $user->lname . ' was submitted by ' . $auth_user_evaluator->fname . ' ' . $auth_user_evaluator->lname);

                User::with('roles')
                    ->whereHas('roles', fn($q) => $q->where('name', 'hr')->orWhere('name', 'admin'))
                    ->chunk(100, function ($hrs) use ($notificationData)
                        {
                            Notification::send($hrs, $notificationData);
                        }
                    );

            });

            return response()->json(
                [
                    'message' => 'Submitted successfully.',
                ]
                ,201
            );

        } catch (\Throwable $e) {
            return response()->json(
                [
                    'message' => $e->getMessage(),
                ],
                500
            );
        }
    }

    public function HoBasic(HoBasic $validated, User $user)
    {
        try {
            DB::transaction(function () use ($validated, $user) {

                $auth_user_evaluator = Auth::user();

                $status = '';
                $approver1 = null;
                $approver2 = null;
                $approverModel = $this->getApprovers($auth_user_evaluator->id);

                if(!$approverModel || $approverModel->isEmpty()){
                    $status = EvalStatus::pending;
                }else{
                    $status = EvalStatus::pending_approval_1;
                    $approver1 = $approverModel->firstWhere('sequence', 1)?->approver_id;
                    $approver2 = $approverModel->firstWhere('sequence', 2)?->approver_id;
                }

                $evalDateFrom = $validated['coverageFrom'];
                $evalDateTo = $validated['coverageTo'];

                if(!empty($validated['reviewTypeRegular']))
                {
                    [$evalDateFrom, $evalDateTo] = match($validated['reviewTypeRegular'])
                    {
                            "Q1"    =>  QuarterDateRange::Q1->range(),
                            "Q2"    =>  QuarterDateRange::Q2->range(),
                            "Q3"    =>  QuarterDateRange::Q3->range(),
                            "Q4"    =>  QuarterDateRange::Q4->range(),
                    };
                }

                $submission = UsersEvaluation::create(
                    [
                        'employee_id'                   => $user->id,
                        'evaluator_id'                  => $auth_user_evaluator->id,
                        'approver1_id'                  => $approver1,
                        'approver2_id'                  => $approver2,
                        'evaluationType'                => 'HoBasic',
                        'employee_branch_code'          => $user->branch?->branch_code,
                        'rating'                        => $validated['rating'],
                        'percentage'                    => $validated['performanceScore'],
                        'coverageFrom'                  => $evalDateFrom,
                        'coverageTo'                    => $evalDateTo,
                        'reviewTypeProbationary'        => $validated['reviewTypeProbationary'] ?: null,
                        'reviewTypeRegular'             => $validated['reviewTypeRegular'] ?: null,
                        'reviewTypeOthersImprovement'   => $validated['reviewTypeOthersImprovement'] ?: null,
                        'reviewTypeOthersCustom'        => $validated['reviewTypeOthersCustom'] ?: null,
                        'priorityArea1'                 => $validated['priorityArea1'] ?: null,
                        'priorityArea2'                 => $validated['priorityArea2'] ?: null,
                        'priorityArea3'                 => $validated['priorityArea3'] ?: null,
                        'remarks'                       => $validated['remarks'] ?: null,
                        'evaluatorApprovedAt'           => now(),
                        'status'                        => $status
                    ]
                );

                for ($i = 1; $i <= 3; $i++) {
                    $submission->jobKnowledge()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['jobKnowledgeScore' . $i],
                            'comment'               => $validated['jobKnowledgeComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 4; $i++) {
                    $submission->qualityOfWorks()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['qualityOfWorkScore' . $i],
                            'comment'               => $validated['qualityOfWorkComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 3; $i++) {
                    $submission->adaptability()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['adaptabilityScore' . $i],
                            'comment'               => $validated['adaptabilityComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 3; $i++) {
                    $submission->teamworks()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['teamworkScore' . $i],
                            'comment'               => $validated['teamworkComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 4; $i++) {
                    $submission->reliabilities()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['reliabilityScore' . $i],
                            'comment'               => $validated['reliabilityComments' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 4; $i++) {
                    $submission->ethicals()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['ethicalScore' . $i],
                            'explanation'           => $validated['ethicalExplanation' . $i] ?: null,
                        ]
                    );
                }

                for ($i = 1; $i <= 6; $i++) {
                    $submission->managerialSkills()->create(
                        [
                            'users_evaluation_id'   => $submission->id,
                            'question_number'       => $i,
                            'score'                 => $validated['managerialSkillsScore' . $i],
                            'explanation'           => $validated['managerialSkillsExplanation' . $i] ?: null,
                        ]
                    );
                }

                //notification for employee
                $user->notify(new EvalNotifications('An evaluation submitted by ' . $auth_user_evaluator->fname . ' ' . $auth_user_evaluator->lname . ' is awaiting your sign.'));

                //notification for admin and hr
                $notificationData = new EvalNotifications('A new evaluation submitted for ' . $user->fname . ' ' . $user->lname . ' was submitted by ' . $auth_user_evaluator->fname . ' ' . $auth_user_evaluator->lname);

                User::with('roles')
                    ->whereHas('roles', fn($q) => $q->where('name', 'hr')->orWhere('name', 'admin'))
                    ->chunk(100, function ($hrs) use ($notificationData)
                        {
                            Notification::send($hrs, $notificationData);
                        }
                    );
            });

            return response()->json(
                [
                    'message' => 'Submitted successfully.',
                ],
                201
            );

        } catch (\Throwable $e) {
            return response()->json(
                [
                    'message' => $e->getMessage(),
                ],
                500
            );
        }
    }
}
