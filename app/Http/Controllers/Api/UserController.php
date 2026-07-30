<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Branch;
use App\Models\Department;
use App\Models\Position;
use Illuminate\Http\Request;
use App\Models\User;
use App\Notifications\EvalNotifications;
use Carbon\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Spatie\Permission\Models\Role;
// use App\Mail\BulkRegister;
use Illuminate\Support\Facades\Mail;

use function Laravel\Prompts\select;
use function Symfony\Component\Clock\now;

class UserController extends Controller
{
    //Create
    public function bulkRegisterUser(Request $request)
    {
        $data = $request->users;
        $user = [];
        $temp_pass = Hash::make('Smct123456');

        $request->validate(
            [
                'users'                 => ['required', 'array'],
                'users.*.fname'         => ['required', 'string'],
                'users.*.lname'         => ['required', 'string'],
                'users.*.date_hired'    => ['required', 'date'],
                'users.*.email'         => ['required', 'email', 'string'],
                'users.*.position_id'   => ['required'],
                'users.*.branch_id'     => ['required'],
                'users.*.department_id' => ['nullable'],
                'users.*.employee_id'   => ['required'],
                'users.*.contact'       => ['required', 'string'],
            ],
            [
                'users.*.fname.required'       => 'First name is required for each user. Please check the uploaded file.',
                'users.*.lname.required'       => 'Last name is required for each user. Please check the uploaded file.',
                'users.*.date_hired.required'  => 'Date hired is required for each user. Please check the uploaded file.',
                'users.*.email.required'       => 'Email is required for each user. Please check the uploaded file.',
                'users.*.position_id.required' => 'Position is required for each user. Please check the uploaded file.',
                'users.*.branch_id.required'   => 'Branch Code is required for each user. Please check the uploaded file.',
                'users.*.employee_id.required' => 'Employee ID is required for each user. Please check the uploaded file.',
                'users.*.contact.required'     => 'Contact number is required for each user. Please check the uploaded file.',
            ]
        );

        foreach ($data as $item) {
            // $temp_pass = Str::random(10);

            $position = Position::firstOrCreate(
                [
                    'label' => $item['position_id'],
                ],
                [
                    'label'         => $item['position_id'],
                    'value'         => $item['position_id'],
                    'created_at'    => now(),
                    'updated_at'    => now(),
                ],
            );

            $department_id = null;
            if (!empty($item['department_id'])) {
                $department = Department::firstOrCreate(
                    [
                        'department_name'   => $item['department_id'],
                    ],
                    [
                        'department_name'   => $item['department_id'],
                        'created_at'        => now(),
                        'updated_at'        => now(),
                    ],
                );
                $department_id = $department->id;
            }

            $username = $item['username'] ?: Str::replace(' ', '_', Str::lower($item['fname'])) . '_' . Str::substr((string) $item['employee_id'], 0, 4);

            $clean_contact = '0' . Str::substr($item['contact'], -10);

            $branch = Branch::firstOrCreate(
                [
                    'branch_code'   => $item['branch_id'],
                ],
                [
                    'branch_code'   => $item['branch_id'],
                    'branch_name'   => $item['branch_id'] . '_SMCT',
                    'branch'        => 'Strong Moto Centrum, Inc.',
                    'acronym'       => 'SMCT',
                    'created_at'    => now(),
                    'updated_at'    => now(),
                ],
            );

            $isUserExist = User::where(
            fn($q)
            =>
            $q->where('fname', $item['fname'])
                ->where('lname', $item['lname'])
                ->where('email', $item['email'])
            )
            ->exists();

            if (!$isUserExist) {
                $user[] =
                [
                    'position_id'    => $position->id,
                    'branch_id'      => $branch?->id,
                    'department_id'  => $department_id ?: null,
                    'date_hired'     => Carbon::parse($item['date_hired'])->toDateString() ?: now(),
                    'username'       => $username,
                    'fname'          => $item['fname'] ?: 'temp_first_name',
                    'lname'          => $item['lname'] ?: 'temp_last_name',
                    'email'          => Str::lower($item['email']) ?: Str::lower($item['fname']).'temp_email@temp.test',
                    'password'       => $temp_pass,
                    'contact'        => $clean_contact ?: 'temp_contact',
                    'emp_id'         => $item['employee_id'] ?: 'tempId',
                    'is_active'      => 'active',
                    'signature'      => null,
                    'avatar'         => null,
                    'created_at'     => now(),
                    'updated_at'     => now(),
                ];
            }
        }

        User::insert($user);

        $userItems = User::whereIn('username', collect($user)->pluck('username'))->get();

        $userItems->each(function ($user) {
            $user->assignRole('employee');
            // Mail::to($user->email)->queue(new BulkRegister($user->fname, $user->lname, $user->username, $user->email, $user->password));
        });

        return response()->json(
            [
                'message' => 'users successfully created',
            ],
            201
        );
    }

    public function registerUser(Request $request)
    {
        $validate = $request->validate(
            [
                'fname'           => ['required', 'string'],
                'lname'           => ['required', 'string'],
                'date_hired'      => ['required', 'date'],
                'email'           => ['required', Rule::unique('users', 'email'), 'email', 'string', 'lowercase'],
                'position_id'     => ['required', Rule::exists('positions', 'id')],
                'branch_id'       => ['required', Rule::exists('branches', 'id')],
                'department_id'   => ['nullable', Rule::exists('departments', 'id')],
                'signature'       => ['required', 'file'],
                'employee_id'     => ['required', Rule::unique('users', 'emp_id')],
                'username'        => ['required', 'string', Rule::unique('users', 'username')],
                'contact'         => ['required', 'string'],
                'password'        => ['required', 'string', 'min: 8', 'max:20'],
            ]
        );

        //file handling | storing
        if ($request->hasFile('signature')) {
            $signature = $request->file('signature');
            $name = time() . '-' . $validate['username'] . '.' . $signature->getClientOriginalExtension();
            $path = $signature->storeAs('user-signatures', $name, 'public');
        } else {
            return response()->json(
                [
                    'message' => 'Signature not found or invalid file.',
                ],
                400
            );
        }

        $user = User::create(
            [
                'fname'         => $validate['fname'],
                'lname'         => $validate['lname'],
                'date_hired'    => $validate['date_hired'],
                'email'         => $validate['email'],
                'position_id'   => $validate['position_id'],
                'department_id' => $validate['department_id'],
                'signature'     => $path ?: null,
                'emp_id'        => $validate['employee_id'],
                'username'      => $validate['username'],
                'contact'       => $validate['contact'],
                'password'      => $validate['password'],
                'branch_id'     => $validate['branch_id'],
            ]
        );

        $user->assignRole('employee');

        //notification for admin and hr
        $notificationData = new EvalNotifications('New user registration: ' . $user->fname . ' ' . $user->lname);

        User::with('roles')
            ->whereHas('roles', fn($q) => $q->where('name', 'hr')->orWhere('name', 'admin'))
            ->chunk(100, function ($hrs) use ($notificationData) {
                Notification::send($hrs, $notificationData);
            });

        return response()->json(
            [
                'message' => 'Registered Successfully',
            ],
            201
        );
    }

    public function store(Request $request)
    {
        $validate = $request->validate(
            [
                'fname'             => ['required', 'string'],
                'lname'             => ['required', 'string'],
                'date_hired'        => ['required', 'date'],
                'email'             => ['required', Rule::unique('users', 'email'), 'email', 'string', 'lowercase'],
                'position_id'       => ['required', Rule::exists('positions', 'id')],
                'branch_id'         => ['required', Rule::exists('branches', 'id')],
                'department_id'     => ['nullable', Rule::exists('departments', 'id')],
                'employee_id'       => ['required', Rule::unique('users', 'emp_id')],
                'username'          => ['required', 'string', Rule::unique('users', 'username')],
                'contact'           => ['required', 'string'],
                'password'          => ['required', 'string', 'min: 8', 'max:20'],
                'role_id'           => ['required', Rule::exists('roles', 'id')],
            ]
        );

        $user = User::create(
            [
                'fname'         => $validate['fname'],
                'lname'         => $validate['lname'],
                'date_hired'    => $validate['date_hired'],
                'email'         => $validate['email'],
                'position_id'   => $validate['position_id'],
                'department_id' => $validate['department_id'] ?: null,
                'emp_id'        => $validate['employee_id'],
                'username'      => $validate['username'],
                'contact'       => $validate['contact'],
                'password'      => $validate['password'],
                'is_active'     => 'active',
                'branch_id'     => $validate['branch_id'],
            ]
        );

        $role = Role::findOrFail($validate['role_id']);
        $user->assignRole($role->name);

        return response()->json(
            [
                'message' => 'Registered Successfully',
            ],
            201
        );
    }

    //Auth
    public function userLogin(Request $request)
    {
        $request->validate(
            [
                'email'     => ['required', 'string'],
                'password'  => ['required', 'string'],
            ]
        );

        $user = User::whereAny(['username', 'email'], $request->email)->first();

        if (!$user) {
            return response()->json(
                [
                    'message' => 'Username or email not found',
                ],
                404
            );
        }

        if ($user->is_active === 'pending') {
            return response()->json(
                [
                    'message' => 'Your account is not activated yet. Please wait for admin to approve.',
                ],
                401
            );
        }

        $credentials = [
            'username' => !filter_var($request->email, FILTER_VALIDATE_EMAIL) ? $request->email : $user->username,
            'password' => $request->password,
        ];

        if (!Auth::attempt($credentials)) {
            return response()->json(
                [
                    'message' => 'Email and password do not match our records',
                ],
                400
            );
        }

        $role = $user->getRoleNames();

        return response()->json(
            [
                'role'      => $role,
                'message'   => 'Login successful. Redirecting you to Dashboard',
            ],
            200
        );
    }

    public function getEvaluatorsByBranch(User $user)
    {
        $userBranch = array_merge($user->branches()->pluck('branches.id')->toArray(), [$user->branch_id]);
        $users = User::select(['id', 'fname', 'lname', 'email'])
                        ->where(
                        fn($q) =>
                            $q->whereHas('branch', fn($q)=>$q->whereIn('branches.id', $userBranch ) )
                            ->orWhereHas('branches', fn($q)=>$q->whereIn('branches.id', $userBranch) )
                        )
                        // ->whereDoesntHave('assigned_as_evaluators')
                        ->whereNot('id', $user->id)
                        ->whereRelation('roles' , 'name', 'evaluator')
                        ->get();

        $user->load(
            [
                'assigned_as_approvers' => function ($q) {
                    $q->select('users.id', 'fname', 'lname', 'email')
                        ->orderBy('sequence', 'asc');
                }
            ]
        );


        return response()->json(
            [
                'users'                 =>  $users,
                'assigned_approver'     =>  $user->assigned_as_approvers
            ]
            ,200
        );
    }

    public function getAllPendingUsers(Request $request)
    {
        $perPage = $request->input('per_page', 10);
        $search_filter = $request->input('search');

        $pending_users = User::query()
            ->select(
                [
                    'id',
                    'position_id',
                    'branch_id',
                    'department_id',
                    'date_hired',
                    'username',
                    'fname',
                    'lname',
                    'email',
                    'contact',
                    'emp_id'
                ]
            )
            ->with(
                [
                    'branch:id,branch_code,branch_name',
                    'branches:id,branch_code,branch_name',
                    'departments:id,department_name',
                    'positions:id,label',
                    'roles:id,name',
                ]
            )
            ->whereNot('is_active', 'active')->whereNot('id', Auth::id())
            ->whereRelation('roles', fn($q) => $q->whereNot('name', 'admin'))
            ->search($search_filter)->latest('id')
            ->paginate($perPage);

        return response()->json(
            [
                'message' => 'ok',
                'users' => $pending_users,
            ],
            200
        );
    }

    public function getAllActiveUsers(Request $request)
    {
        $perPage = $request->input('per_page', 10);
        $role_filter = $request->input('role');
        $search_filter = $request->input('search');
        $branch_filter = $request->input('branch');
        $department_filter = $request->input('department');

        $users = User::query()
            ->select(
                [
                    'id',
                    'position_id',
                    'branch_id',
                    'department_id',
                    'date_hired',
                    'username',
                    'fname',
                    'lname',
                    'email',
                    'contact',
                    'emp_id'
                ]
            )
            ->with(
                [
                    'branch:id,branch_code,branch_name',
                    'departments:id,department_name',
                    'positions:id,label',
                    'roles:id,name',
                    'assignedEvaluators:id,fname,lname,email'
                ]
            )
            ->where('is_active', 'active')
            ->whereNot('id', Auth::id())
            ->when($role_filter, fn($role) => $role->whereRelation('roles', 'id', $role_filter))
            ->when($branch_filter,
                fn($q) =>
                    $q->where( fn($query) => $query->whereRelation('branches', 'branches.id', $branch_filter)
                    ->orWhereRelation('branch', 'branches.id', $branch_filter)
            ))
            ->when($department_filter, fn($q) => $q->where('department_id', $department_filter))
            ->whereRelation('roles', fn($q) => $q->whereNot('name', 'admin'))
            ->search($search_filter)
            ->latest('id')
            ->paginate($perPage);

        return response()->json(
            [
                'message'   => 'ok',
                'users'     => $users,
            ],
            200
        );
    }

    public function getSubordinate(Request $request)
    {
        $branch = $request->input('branch_id') ?: 126;
        $perPage = $request->input('per_page',10);
        $department = $request->input('department_id');

        $evaluators = User::select(
                            [
                                'id',
                                'position_id',
                                'fname',
                                'lname',
                                'email'
                            ]
                        )
                        ->with(
                            [
                                'positions:id,label',
                            ]
                        )
                            ->where('is_active','active')
                            ->where('branch_id', $branch)
                            ->when($department , fn($q) => $q->where('department_id', $department))
                            ->whereRelation('roles', fn($q) => $q->where('name', 'evaluator')->orWhere('name', 'hr'))
                            ->paginate($perPage);

        $employees = User::select(
                            [
                                'id',
                                'position_id',
                                'fname',
                                'lname',
                                'email'
                            ]
                        )
                        ->with(
                            [
                                'positions:id,label',
                            ]
                        )
                        ->where('is_active','active')
                        ->where('branch_id', $branch)
                        ->when($department , fn($q) => $q->where('department_id', $department))
                        ->whereRelation('roles', 'name', 'employee')
                        ->paginate($perPage);

        return response()->json(
            [
                'evaluators'        =>  $evaluators,
                'employees'         =>  $employees
            ]
            ,200
        );
    }

    public function getAllEvaluators(Request $request)
    {
        $per_page = $request->input('per_page',10);
        $search = $request->input('search');

        $evaluators = User::select(
                    [
                        'id',
                        'position_id',
                        'branch_id',
                        'fname',
                        'lname',
                        'email'
                    ]
                )
                ->with(
                    [
                        'branch:id,branch_code,branch_name',
                        'positions:id,label',
                        'roles:id,name',
                    ]
                )
                ->where( fn($q) => $q->whereNot('fname' ,'HR')->orWhereNot('lname' ,'Administrator')->orWhereNot('email' ,'hr@smct.com'))
                ->where(
                    fn($q)
                    =>
                    $q->where('is_active', 'active')
                    // ->whereNot('id',Auth::id())
                )
                ->whereRelation('roles', fn($w) => $w->where(fn($q) => $q->where('name', 'evaluator')->orWhere('name', 'hr')))
                ->search($search)
                ->paginate($per_page);

        return response()->json(
            [
                'message'       =>  'List of all evaluator',
                'evaluators'    =>  $evaluators
            ]
            ,200
        );
    }

    public function showUser(User $user)
    {
        $shownUser = $user->load(
            [
                'branch:id,branch_code,branch_name',
                'branches:id,branch_code,branch_name',
                'departments:id,department_name',
                'positions:id,label',
                'roles:id,name',
                'evaluations',
                'doesEvaluated',
            ]
        );

        return response()->json(
            [
                'data' => $shownUser,
            ]
            ,200
        );
    }

    public function getAllBranchHeads(Request $request)
    {
        $search = $request->input('search');
        // $per_page = $request->input('per_page', 10);

        $users = User::query()
            ->select(
                [
                    'id',
                    'branch_id',
                    'fname',
                    'lname'
                ]
            )
            ->with(
                [
                    'branch:id,branch_code,branch_name',
                    'branches:id,branch_code,branch_name',
                ]
            )
            ->where('is_active', 'active')
            ->search($search)
            ->whereIn('position_id', [35, 36, 37, 38]) // <--- all branch_manager/supervisor position id
            ->latest('id')
            ->get();
            // ->paginate($per_page);

        return response()->json(
            [
                'branch_heads' => $users,
            ]
            ,200
        );
    }

    public function getAllAreaManager(Request $request)
    {
        $search = $request->input('search');
        // $per_page = $request->input('per_page', 10);

        $users = User::query()
            ->select(['id','branch_id','fname', 'lname'])
            ->with(
                [
                    'branch:id,branch_code,branch_name',
                    'branches:id,branch_code,branch_name'
                ]
            )
            ->where('is_active', 'active')
            ->search($search)
            ->where('position_id', 16)
            ->latest('id')
            ->get();
            // ->paginate($per_page);

        return response()->json(
            [
                'branch_heads' => $users,
            ]
            ,200
        );
    }

    public function getAllSignatureRequest(Request $request)
    {
        $search = $request->input('search');
        $per_page = $request->input('per_page', 10);

        $users = User::query()->with(
                [
                    'branch:id,branch_code,branch_name',
                    'branches:id,branch_code,branch_name',
                    'departments:id,department_name',
                    'positions:id,label'
                ]
            )
            ->where('requestSignatureReset', true)
            ->whereNot('approvedSignatureReset', true)
            ->search($search)
            ->latest('id')
            ->paginate($per_page);

        return response()->json(
            [
                'users' => $users,
            ]
            ,200
        );
    }

    public function getAllEvaluatorAssignedEmployees(Request $request,User $user)
    {
        $perPage = $request->input('per_page', 10);
        $search = $request->input('search');

        $employees = $user->assignedEmployees()
                        ->select(['users.id', 'position_id', 'department_id','branch_id', 'fname', 'lname', 'email'])
                        ->with(
                            [
                                'branch:id,branch_code,branch_name',
                                'positions:id,label',
                                'roles:id,name',
                                'employeeLastEvaluation:id,users_evaluations.employee_id,reviewTypeProbationary,reviewTypeRegular,created_at',
                            ]
                        )
                        ->search($search)
                        ->latest('id')
                        ->paginate($perPage);

        return response()->json(
            [
                'message'       =>  'List of assigned employees under specific evaluator',
                'employees'     =>  $employees
            ]
            ,200
        );
    }

    //applicable for area manager / branch manager/supervisor /department manager / avp manager
    public function getAllEmployeeByAuth(Request $request)
    {
        $manager = Auth::user();

        $search = $request->input('search');
        $position_filter = $request->input('position_filter');
        $perPage = $request->input('per_page', 10);

        if (!$manager->roles()->where('name', 'evaluator')->orWhere('name', 'hr')->exists())
        {
            return response()->json(
                [
                    'error' => 'Auth user is not a evaluator or hr.',
                    $manager->roles()->pluck('name'),
                ],
                401
            );
        }

        $userQuery = User::query()
                        ->with(
                            [
                                'branch:id,branch_code,branch_name',
                                'branches:id,branch_code,branch_name',
                                'departments:id,department_name',
                                'positions:id,label',
                                'roles:id,name',
                                'assignedEvaluators' => function ($query) {
                                    $query->select('users.id', 'fname', 'lname', 'email')
                                        ->with([
                                            'assigned_as_approvers:id,fname,lname,email'
                                        ]);
                                },
                            ]
                        )
                        ->select(
                            [
                                "id",
                                "position_id",
                                "department_id",
                                "branch_id",
                                "fname",
                                "lname",
                                "email",
                                "emp_id",
                                "date_hired"
                            ]
                        )
                        ->where('is_active', 'active')
                        ->whereRelation('assignedEvaluators', 'evaluator_id', $manager->id)
                        ->when($position_filter, fn($q) => $q->whereRelation('positions','id', $position_filter))
                        ->search($search)
                        ->latest('id');

        $new_hires = (clone $userQuery)->whereBetween('created_at', [Carbon::now()->subDays(7), now()])->count();

        $employees = $userQuery->paginate($perPage);

        $positions_4_filter = Position::whereHas( 'users',
                                    function ($query) use ($manager) {
                                        $query->where('is_active', 'active')
                                        ->whereRelation('assignedEvaluators', 'evaluator_id', $manager->id);
                                    }
                                )
                                ->get(
                                    [
                                        'id',
                                        'label'
                                    ]
                                );

        return response()->json(
            [
                'employees' => $employees,
                'new_count' => $new_hires,
                'positions' => $positions_4_filter,
            ]
            ,200
        );
    }

    public function getAllEvaluatorEmployees(Request $request, User $user)
    {
        $search = $request->input('search');

        $unassignedEmp = User::query()
                            ->select(['id','fname','lname','position_id','branch_id', 'email'])
                            ->with(
                                [
                                    'branch:id,branch_code,branch_name',
                                    'positions:id,label',
                                    'roles:id,name',
                                ]
                            )
                            ->where('is_active', 'active')
                            ->search($search)
                            ->whereDoesntHave('assignedEvaluators')
                            ->get();

        //boolean conditions
        // $isHO = ($user->branches()->where('branch_id', 126)->exists() || $user->branch_id === 126 );
        // $hasDepartment = !empty($user->department_id);
        // $isAreaManager = $user->position_id === 16;
        // $isAVP = $user->position_id === 31;

        // //ids
        // $branches = $user->branches->pluck('id')->toArray();
        // $areaManagerPositionId = [16];
        // $branchManagerPositionsId = [35, 36, 37, 38];

        // $employees = User::query()
        //     ->with(
        //         [
        //             'branch:id,branch_code,branch_name',
        //             'branches:id,branch_code,branch_name',
        //             'departments:id,department_name',
        //             'positions:id,label',
        //             'roles:id,name',
        //         ]
        //     )
        //     ->where( fn($q) => $q->whereNot('fname' ,'HR')->orWhereNot('lname' ,'Administrator')->orWhereNot('email' ,'hr@smct.com'))
        //     ->doesntHave('assignedEvaluators')
        //     ->where('is_active', 'active')
        //     ->where( fn ($q) =>
        //         $q->whereRelation('branch', fn($query) => $query->whereIn('branches.id',array_merge([$user->branch_id], $branches)))
        //         ->orWhereRelation('branches', fn($query) => $query->whereIn('branches.id',array_merge([$user->branch_id], $branches)))
        //     )
        //     ->where('id', '!=', $user->id)
        //     ->when($isAreaManager, function ($q) use ($branchManagerPositionsId) {
        //         $q->whereIn('position_id', $branchManagerPositionsId);
        //     })
        //     ->when(!$isHO && in_array($user->position_id, $branchManagerPositionsId) && !$hasDepartment, function ($q) use ($areaManagerPositionId, $branchManagerPositionsId) {
        //         $q->whereNotIn('position_id', array_merge($areaManagerPositionId));
        //     })
        //     ->when($isHO && $hasDepartment && !$isAVP, function ($q) use ($user) {
        //         $q->where('department_id', $user->department_id);
        //         // ->whereRelation('positions', fn($q) => $q->whereNotLike('positions.label', '%manager%'));
        //     })
        //     ->when(!$isHO && !$hasDepartment && !in_array($user->position_id, array_merge($areaManagerPositionId, $branchManagerPositionsId)), function ($q) use ($areaManagerPositionId, $branchManagerPositionsId) {
        //         $q->whereNotIn('position_id', array_merge($areaManagerPositionId));
        //     })
        //     ->when($isAVP && $isHO && $hasDepartment, function ($q) use ($user) {
        //         $q->where('department_id', $user->department_id)->orWhereRelation('positions', 'id',  16);
        //     })
        //     ->search($search)
        //     ->latest('id')
        //     ->get();

            return response()->json(
                [
                    'message'       =>  'List of under employees unassigned yet.',
                    'employees'     =>  $unassignedEmp
                ]
                ,200
            );
    }

    //update
    public function updateUser(Request $request, User $user)
    {
        $validate = $request->validate(
            [
                'fname'         => ['required', 'string'],
                'lname'         => ['required', 'string'],
                'date_hired'    => ['required', 'date'],
                'email'         => ['required', 'string', 'email', 'lowercase', Rule::unique('users', 'email')->ignore($user->id)],
                'position_id'   => ['required', Rule::exists('positions', 'id')],
                'branch_id'     => ['required', Rule::exists('branches', 'id')],
                'department_id' => ['nullable', Rule::exists('departments', 'id')],
                'employee_id'   => ['required', Rule::unique('users', 'emp_id')->ignore($user->id)],
                'username'      => ['required', 'string', Rule::unique('users', 'username')->ignore($user->id)],
                'contact'       => ['required', 'string'],
                'roles'         => ['required', Rule::exists('roles', 'name')],
                'password'      => ['nullable', 'string', 'min: 8', 'max:20'],
            ]
        );

        $user->syncRoles([$validate['roles']]);

        $updateData = [
            'fname'         => $validate['fname'],
            'lname'         => $validate['lname'],
            'date_hired'    => $validate['date_hired'],
            'email'         => $validate['email'],
            'position_id'   => $validate['position_id'],
            'department_id' => $validate['department_id'] ?: null,
            'username'      => $validate['username'],
            'contact'       => $validate['contact'],
            'emp_id'        => $validate['employee_id'],
            'branch_id'     => $validate['branch_id']
        ];

        if ($request->filled('password'))
        {
            $updateData['password'] = $validate['password'];
        }

        $user->update($updateData);

        return response()->json(
            [
                'message' => 'Updated Successfully',
            ]
            ,200
        );
    }

    public function updateProfileUserAuth(Request $request)
    {
        $user = Auth::user();
        if (!$user)
        {
            return response()->json(
                [
                    'message' => 'Unauthenticated.',
                ],
                401
            );
        }

        if (empty($request->signature) && empty($user->signature))
        {
            return response()->json(
                [
                    'message' => 'Signature is required',
                ],
                422
            );
        }

        $validated = $request->validate(
            [
                'username'          => ['nullable', 'string'],
                'email'             => ['nullable', 'email'],
                'current_password'  => ['required', 'current_password:sanctum'],
                'new_password'      => ['nullable', 'required_with:confirm_password'],
                'confirm_password'  => ['nullable', 'required_with:new_password', 'same:new_password'],
            ]
        );

        $items = [
            'username'  => $validated['username'] ?: $user->username,
            'email'     => $validated['email'] ?: $user->email,
        ];

        if ($request->filled('new_password') && $request->filled('confirm_password'))
        {
            $items['password'] = $validated['confirm_password'];
        }

        //file handling | storing
        if ($request->file('signature'))
        {
            $signature = $request->file('signature');
            $name = time() . '-' . $user->username . '.' . $signature->getClientOriginalExtension();
            $path = $signature->storeAs('user-signatures', $name, 'public');

            if ($user->signature) {
                if (Storage::disk('public')->exists($user->signature))
                {
                    Storage::disk('public')->delete($user->signature);
                } else {
                    return response()->json(
                        [
                            'message' => 'signature not found',
                        ],
                        402
                    );
                }
            }
            $items['signature'] = $path;
            $items['requestSignatureReset'] = false;
            $items['approvedSignatureReset'] = false;
        }

        $user->update($items);

        return response()->json(
            [
                'message'   => 'Uploaded Successfully',
            ]
            ,200
        );
    }

    public function requestSignatureReset()
    {
        $user = Auth::user();

        $user->update(
            [
                'requestSignatureReset' => true,
            ]
        );

        $notificationData = new EvalNotifications('Signature reset request from: ' . $user->fname . ' ' . $user->lname);

        User::with('roles')
            ->whereHas('roles', fn($q) => $q->where('name', 'hr')->orWhere('name', 'admin'))
            ->chunk(100, function ($hrs) use ($notificationData) {
                    Notification::send($hrs, $notificationData);
                }
            );

        return response()->json(
            [
                'message' => 'Approved',
            ]
            ,200
        );
    }

    public function approvedSignatureReset(User $user)
    {
        if ($user->signature) {
            if (Storage::disk('public')->exists($user->signature))
            {
                Storage::disk('public')->delete($user->signature);

                $user->update(
                    [
                        'approvedSignatureReset' => true,
                        'signature' => null,
                    ]
                );
                $user->notify(new EvalNotifications('Your signature reset request has been approved.'));

                return response()->json(
                    [
                        'message' => 'Approved',
                    ],
                    201
                );
            } else {
                return response()->json(
                    [
                        'message' => 'User signature not found',
                    ]
                    ,402
                );
            }
        }

        return response()->json(
            [
                'message' => 'User doesnt have a signature',
            ]
            ,402
        );
    }

    public function rejectSignatureReset(User $user)
    {
        $user->update(
            [
                'requestSignatureReset' => false,
            ]
        );

        $user->notify(new EvalNotifications('Unfortunately, your signature reset request has been declined.'));

        return response()->json(
            [
                'message' => 'Rejected Successfully',
            ]
            ,200
        );
    }

    public function approveRegistration(User $user)
    {
        $user->update(
            [
                'is_active' => 'active',
            ]
        );

        return response()->json(
            [
                'message' => 'Approved',
            ]
            ,200
        );
    }

    public function updateUserBranch(User $user, Request $request)
    {
        $branchIds = is_array($request->branch_ids)
            ? $request->branch_ids
            : explode(',', $request->branch_ids);

        $user->branches()->sync($branchIds);

        return response()->json(
            [
                'message' => 'User Branch Updated',
            ]
            ,200
        );
    }

    public function assignEmployees(User $user, Request $request)
    {
        $Ids = $request->employee_ids ?: [];
        $employeeIds = is_array($Ids)
                ? $Ids
                : explode(',', $Ids);

        $user->assignedEmployees()->sync($employeeIds);

        return response()->json(
            [
                'message'   =>  "success"
            ]
            ,201
        );
    }

    public function assignApprovers(User $user,Request $request)
    {
        $syncData = [];

        foreach ($request->approver_ids as $index => $approverId)
        {
            $syncData[$approverId] = [
                'sequence' => $index + 1,
            ];
        }

        $user->assigned_as_approvers()->sync($syncData);

        return response()->json(
            [
                'message'   => 'Assigned successfully'
            ]
        );
    }

    public function removeUserBranches(User $user)
    {
        $user->branches()->detach();

        return response()->json(
            [
                'message' => 'All user assigned branches removed',
            ]
            ,200
        );
    }

    //destroy || delete
    public function deleteUser(User $user)
    {
        // UsersEvaluation::where('employee_id', $user->id)->orWhere('evaluator_id', $user->id)->delete();
        $user->delete();

        return response()->json(
            [
                'message' => 'Deleted Successfully',
            ]
            ,204
        );
    }
}
