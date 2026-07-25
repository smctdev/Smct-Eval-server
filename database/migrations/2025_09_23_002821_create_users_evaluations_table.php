<?php

use App\Models\User;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('users_evaluations', function (Blueprint $table) {
            $table->id();
            $table->foreignIdFor(User::class, 'employee_id')->constrained()->cascadeOnDelete();
            $table->foreignIdFor(User::class, 'evaluator_id')->constrained()->cascadeOnDelete();
            $table->foreignIdFor(User::class, 'approver1_id')->nullable()->constrained()->nullOnDelete();
            $table->foreignIdFor(User::class, 'approver2_id')->nullable()->constrained()->nullOnDelete();
            $table->foreignIdFor(User::class, 'rejected_by_id')->nullable()->constrained()->nullOnDelete();

            $table->string('employee_branch_code');

            $table->decimal('rating', 3, 2);
            $table->string('percentage');
            $table->enum('status', ['pending', 'pending_approval_1', 'pending_approval_2', 'rejected', 'completed'])->default('pending');
            $table->enum('evaluationType', ['HoBasic', 'HoRankNFile', 'BranchBasic', 'BranchRankNFile','BranchBasicAreaManager']);

            $table->date('coverageFrom');
            $table->date('coverageTo');
            $table->integer('reviewTypeProbationary')->nullable();

            $table->string('reviewTypeRegular')->nullable();
            $table->boolean('reviewTypeOthersImprovement')->nullable();
            $table->string("reviewTypeOthersCustom")->nullable();

            $table->text("priorityArea1");
            $table->text("priorityArea2")->nullable();
            $table->text("priorityArea3")->nullable();

            $table->text("remarks")->nullable();
            $table->text("noteIfRejected")->nullable();

            $table->date('evaluatorApprovedAt');
            $table->date('firstApproverApprovedAt')->nullable();
            $table->date('secondApproverApprovedAt')->nullable();
            $table->date('employeeApprovedAt')->nullable();

            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('users_evaluations');
    }
};
