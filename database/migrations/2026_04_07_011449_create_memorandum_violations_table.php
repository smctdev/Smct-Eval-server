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
        Schema::create('memorandum_violations', function (Blueprint $table) {
            $table->id();
            $table->foreignIdFor(User::class, 'user_id')->nullable()->constrained()->nullOnDelete();
            $table->date('violation_date');
            $table->string('violation_title');
            $table->string('summary');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('memorandum_violations');
    }
};
