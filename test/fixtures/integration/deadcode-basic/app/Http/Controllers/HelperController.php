<?php

namespace App\Http\Controllers;

final class HelperController
{
    public static function reachableHelper()
    {
        return response()->json([
            'helper' => true,
        ], 200);
    }

    public static function unusedHelper()
    {
        return response()->json([
            'unused_helper' => true,
        ], 200);
    }
}
