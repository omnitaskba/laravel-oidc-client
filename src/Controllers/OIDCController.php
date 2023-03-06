<?php

namespace Maicol07\OIDCClient\Controllers;

use Exception;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Session;
use Illuminate\Validation\ValidationException;
use Maicol07\OIDCClient\Auth\OIDCGuard;

class OIDCController extends Controller
{
    use ValidatesRequests;
    use AuthorizesRequests;
    use DispatchesJobs;

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
    }

    /**
     * @throws Exception
     */
    final public function login(): RedirectResponse
    {
        return redirect()->away($this->guard()->getAuthorizationUrl());
    }

    /**
     * @throws Exception
     */
    final public function callback(Request $request): null|RedirectResponse
    {
        $user = $this->guard()->generateUser();

        if ($this->guard()->login($user)) {
            $request->session()->regenerate();

            return redirect()->intended(config('oidc.redirect_path_after_login'));
        }

        throw ValidationException::withMessages([
            'user' => [trans('auth.failed')],
        ]);
    }

    final public function logout(Request $request): RedirectResponse
    {
        $this->guard()->logout();
        $user = Auth::user(); 

        $request->session()->invalidate();
        Session::flush();

        if($user){
            return redirect('https://dev-sso.dermalogica.co.uk/oxauth/restv1/end_session?id_token_hint='. $user->id_token .'&=post_logout_redirect_uri' . config('oidc.redirect_path_after_logout'))->intended(config('oidc.redirect_path_after_logout'));
        }else{
            return redirect()->intended(config('oidc.redirect_path_after_logout'));
        }
       
    }

    private function guard(): StatefulGuard|OIDCGuard
    {
        return Auth::guard();
    }
}
