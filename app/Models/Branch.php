<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Branch extends Model
{
     protected $guarded=[];

     public function usersBranches(){
         return $this->belongsToMany(User::class, 'branch_user');
    }

    public function userBranch()
    {
        return $this->hasMany(User::class, 'branch_id');
    }

}
