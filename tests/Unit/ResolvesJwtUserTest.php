<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Maya\Auth\Concerns\ResolvesJwtUser;

// ─── Fake model setup ─────────────────────────────────────────────────────────

/**
 * In-memory model stub that finds "users" from a static map.
 * Avoids any database dependency.
 */
class FakeUser extends Model
{
    public $incrementing = false;

    protected $keyType = 'string';

    /** @var array<string, FakeUser> */
    private static array $store = [];

    public static function seed(string $id): self
    {
        $user = new self();
        $user->id = $id;
        self::$store[$id] = $user;
        return $user;
    }

    public static function clear(): void
    {
        self::$store = [];
    }

    public static function find($id, $columns = ['*']): ?self
    {
        return self::$store[$id] ?? null;
    }
}

/**
 * Controller stub that uses the trait with the default model override.
 */
class FakeController
{
    use ResolvesJwtUser;

    protected function jwtUserModel(): string
    {
        return FakeUser::class;
    }

    public function callResolveJwtUser(Request $request): ?Model
    {
        return $this->resolveJwtUser($request);
    }
}

/**
 * Controller stub that relies on the default model (no override).
 */
class FakeControllerDefault
{
    use ResolvesJwtUser;

    public function callResolveJwtUser(Request $request): ?Model
    {
        return $this->resolveJwtUser($request);
    }
}

beforeEach(function () {
    FakeUser::clear();
});

// ─── resolveJwtUser ───────────────────────────────────────────────────────────

it('returns the model when jwt_user has a valid id and the record exists', function () {
    FakeUser::seed('user-42');

    $request = Request::create('/test', 'GET');
    $request->attributes->set('jwt_user', ['id' => 'user-42']);

    $controller = new FakeController();
    $result = $controller->callResolveJwtUser($request);

    expect($result)->toBeInstanceOf(FakeUser::class);
    expect($result->id)->toBe('user-42');
});

it('returns null when jwt_user attribute is missing', function () {
    $request = Request::create('/test', 'GET');

    $controller = new FakeController();

    expect($controller->callResolveJwtUser($request))->toBeNull();
});

it('returns null when jwt_user id is empty', function () {
    $request = Request::create('/test', 'GET');
    $request->attributes->set('jwt_user', ['id' => '']);

    $controller = new FakeController();

    expect($controller->callResolveJwtUser($request))->toBeNull();
});

it('returns null when the record does not exist in the store', function () {
    $request = Request::create('/test', 'GET');
    $request->attributes->set('jwt_user', ['id' => 'ghost-user']);

    $controller = new FakeController();

    expect($controller->callResolveJwtUser($request))->toBeNull();
});

it('returns null when jwt_user is not an array', function () {
    $request = Request::create('/test', 'GET');
    $request->attributes->set('jwt_user', 'bad-value');

    $controller = new FakeController();

    expect($controller->callResolveJwtUser($request))->toBeNull();
});

// ─── jwtUserModel default ─────────────────────────────────────────────────────

it('uses App\\Models\\User as default model when jwtUserModel is not overridden', function () {
    $controller = new FakeControllerDefault();
    $reflection = new ReflectionMethod($controller, 'jwtUserModel');

    expect($reflection->invoke($controller))->toBe(\App\Models\User::class);
});
