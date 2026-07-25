<?php

use App\Models\UsersEvaluation;
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
        Schema::create('quality_of_works', function (Blueprint $table) {
            $table->id();
            $table->foreignIdFor(UsersEvaluation::class, 'users_evaluation_id')->constrained()->cascadeOnDelete();
            $table->integer('question_number');
            $table->integer('score');
            $table->text('comment')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('quality_of_works');
    }
};
