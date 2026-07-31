<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Mail\ForgotPassword;
use Illuminate\Support\Facades\RateLimiter;
use App\Models\Otp;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use Illuminate\Validation\Rule;

class OtpController extends Controller
{
    //forgot-password
    public function otpRequest(Request $request)
    {
        $validated = $request->validate(
            [
                'email'     =>  ['required', 'email', Rule::exists('users','email')]
            ],
            [
                'email.exists'  =>  'This email address is not registered'
            ]
        );

        $key = 'action:' . $request->ip();

        if (RateLimiter::tooManyAttempts($key, 1)) {
            return response()->json([
                'message' => 'Too many attempts.'
            ], 429);
        }

            $otp = rand(100000,999999);

            $user = User::where('email', $validated['email'])->first();

            $result = Otp::updateOrCreate(
                [
                    'email'         =>  $validated['email'],
                ],
                [
                    'email'         =>  $validated['email'],
                    'otp'           =>  $otp,
                    'expired_at'    =>  now()->addMinutes(3),
                ]
            );

            Mail::to($validated['email'])->queue( new ForgotPassword($user->fname, $user->lname, $user->username, $user->email, $otp));

            if ($result) {
                RateLimiter::hit($key, 5);
            }

            return response()->json(
                [
                    'message'       =>  "Email sent successfully"
                ]
                ,200
            );

    }

    public function otpVerify(Request $request)
    {
        $validated = $request->validate(
            [
                'email'     => ['required', 'email', Rule::exists('otps', 'email')],
                'otp'       => ['required'],
            ],
            [
               'email.exists'  =>  'This email address did not request for otp code yet'
            ]
        );

        $verify = Otp::where('email', $validated['email'])->first();

        if($verify->expired_at->isPast())
        {
            return response()->json(
                [
                    'message'   =>  "This otp has been expired"
                ]
                ,401
            );
        }

        if($verify->otp != $validated['otp'])
        {
            return response()->json(
                [
                    'message'   =>  "Incorrect otp"
                ]
                ,422
            );
        }

        User::where('email', $validated['email'])->update(['isResetPass' => true]);
        $userAuth = User::where('email',$validated['email'])->first();

        Auth::login($userAuth);
        if (!Auth::check())
        {
            return response()->json(
                [
                    'message' => 'Failed to authenticate user'
                ]
                , 401);
        }

        $role = $userAuth->getRoleNames();

        return response()->json(
            [
                'role'      => $role,
                'message'   => 'Login successful. Redirecting you to Dashboard',
            ]
            ,200
        );
    }

}
