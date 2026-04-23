<?php

namespace App\Http\Controllers;

final class ObjectEntryController
{
    public function index()
    {
        return (new HelperController())->reachableInstanceHelper();
    }
}
