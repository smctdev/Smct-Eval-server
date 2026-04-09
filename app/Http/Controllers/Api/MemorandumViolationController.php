<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\MemorandumViolation;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\Rule;

class MemorandumViolationController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $memos = MemorandumViolation::all();

        return response()->json(
            [
                'memos'   => $memos
            ],
            200
        );
    }

    public function auth_index(Request $request)
    {
        $auth_user = Auth::user();

        $search = $request->input('search');
        $month = $request->input('month');
        $page = $request->input('per_page');

        $memos = MemorandumViolation::where('user_id', $auth_user->id)
                   ->when( $search, fn ($q) => $q->whereLike('violation_title', "%{$search}%"))
                   ->when( $month, fn ($q) => $q->whereRaw("DATE_FORMAT(created_at, '%Y-%m') = ?", $month))
                   ->paginate($page);

        return response()->json(
            [
                'memos'   => $memos
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
        $validate = $request->validate(
            [
                'user_id'              => ['required', 'numeric', Rule::exists(User::class, 'id')],
                'violation_date'       => ['required', 'date'],
                'title'                => ['required', 'string'],
                'document'             => ['required', 'file']
            ]
        );


        if($request->hasFile('document'))
        {
               $file  = $request->file('document');
               $name  = time().'-'.$validate['user_id'].'.'.$file->getClientOriginalExtension();
               $path  = $file->storeAs('memo-files', $name, 'public');
        }else{
            return response()->json(
                [
                   'message'   => 'Invalid file or not found.'
                ],
                400
            );
        }

        MemorandumViolation::create(
            [
                'user_id'            =>  $validate['user_id'],
                'violation_date'     =>  $validate['violation_date'],
                'violation_title'    =>  $validate['title'],
                'support_document'   =>  $path ?: null
            ]
        );

        return response()->json(
            [
               'message'   => 'Memo stored successfully'
            ],
            201
        );
    }

    /**
     * Display the specified resource.
     */
    public function show(MemorandumViolation $MemorandumViolation)
    {
        return response()->json(
            [
                'memos' => $MemorandumViolation
            ],
            200
        );

    }

    public function show_perUser($id)
    {
        $memos = MemorandumViolation::where('user_id', $id )->get();

        return response()->json(
            [
                'memos' => $memos
            ],
            200
        );

    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(MemorandumViolation $MemorandumViolation)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, MemorandumViolation $MemorandumViolation)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(MemorandumViolation $MemorandumViolation)
    {
        //
    }
}
