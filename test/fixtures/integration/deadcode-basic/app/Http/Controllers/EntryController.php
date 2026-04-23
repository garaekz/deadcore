<?php

namespace App\Http\Controllers;

final class EntryController
{
    public function index()
    {
        return HelperController::reachableHelper();
    }
}
