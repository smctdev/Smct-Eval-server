<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Branch;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;

class BranchController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $branches = Branch::get(['id','branch_code', 'branch_name']);

        return response()->json(
            [
                'branches' => $branches
            ],
            200
        );
    }

    public function getTotalEmployeesBranch(Request $request)
    {
        $paginate = $request->input('per_page', 10);
        $search = $request->input('search');

        $all = Branch::query()->withCount(
            [
                'userBranch as managers_count' =>
                    fn($user)
                    =>
                    $user->whereHas(
                        'positions',
                        fn($position)
                        =>
                        $position->whereLike('label', "%manager%")
                    ),
                'userBranch as employees_count' =>
                    fn($user)
                    =>
                    $user->whereHas(
                        'positions',
                        fn($position)
                        =>
                        $position->whereNotLike('label', "%manager%")
                    )
            ])
            ->when(
                $search,
                fn($q) =>
                    $q->whereAny(['branch_code', 'branch_name', 'branch', 'acronym'], 'LIKE', "%{$search}%")
            )
            ->paginate($paginate);

        return response()->json(
            [
                'branches' => $all
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
                'branch_code'        => ['required', 'string', 'regex:/^[A-Z0-9\- ]+$/', Rule::unique('branches', 'branch_code')],
                'branch_name'        => ['required', 'string'],
                'branch'             => ['required', 'string'],
                'acronym'            => ['required', 'string', 'regex:/^[A-Z]+$/']
            ]
        );

        Branch::create(
            [
                'branch_code'        => $validate['branch_code'],
                'branch_name'        => $validate['branch_name'],
                'branch'             => $validate['branch'],
                'acronym'            => $validate['acronym']
            ]
        );

        return response()->json(
            [
                'message'       => 'Branch Successfully Created'
            ],
            201
        );
    }

    /**
     * Display the specified resource.
     */
    public function show(Branch $branch)
    {
        return response()->json(
            [
                'branch'        =>  $branch
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
    public function update(Request $request, string $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(Branch $branch)
    {
        $branch->delete();

        return response()->json(
            [
                'message'       =>  'Branch Deleted Successfully'
            ],
            200
        );
    }
}
