<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Notifications\DatabaseNotification as Notification;

class NotificationsController extends Controller
{
    public function isRead(Notification $notification)
    {

        $notification->markAsRead();

        return response()->json(
            [
                'message'         =>  'Mark as read notification',
            ],
            200
        );
    }

    public function markAllAsRead()
    {
        $user = Auth::user();

        $user->unreadNotifications->markAsRead();

        return response()->json(
            [
                'message'       =>  "Successfully read all notifications"
            ],
            200
        );
    }

    public function destroy(Notification $notification)
    {
        $notification->delete();

        return response()->json(
            [
                'message'       =>  "Successfully deleted"
            ],
            200
        );
    }
}
