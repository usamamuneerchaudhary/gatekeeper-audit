<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Controllers;

use Illuminate\Container\Attributes\CurrentUser;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models\Invoice;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models\SoftInvoice;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models\User;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Requests\GuardClauseRequest;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Requests\MagicPropertyRequest;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Requests\NotNullUserRequest;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Requests\OwnerComparisonRequest;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Requests\RouteNameRequest;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Requests\RouteNotNullRequest;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Requests\SignedInRequest;

/**
 * One action per bug fixed in 1.0.3. Each action name says what the audit must conclude.
 */
class RegressionInvoiceController extends Controller
{
    /**
     * FormRequest that only checks auth()->check().
     */
    public function signedIn(SignedInRequest $request, Invoice $invoice): Invoice
    {
        return $invoice;
    }

    /**
     * FormRequest that only checks the user is not null.
     */
    public function notNullUser(NotNullUserRequest $request, Invoice $invoice): Invoice
    {
        return $invoice;
    }

    /**
     * FormRequest with a signed-in guard clause before return true.
     */
    public function guardClause(GuardClauseRequest $request, Invoice $invoice): Invoice
    {
        return $invoice;
    }

    /**
     * FormRequest that reads the route model without checking it.
     */
    public function routeNotNull(RouteNotNullRequest $request, Invoice $invoice): Invoice
    {
        return $invoice;
    }

    /**
     * FormRequest that only inspects the route name.
     */
    public function routeName(RouteNameRequest $request, Invoice $invoice): Invoice
    {
        return $invoice;
    }

    /**
     * FormRequest that checks the routed invoice read as $this->invoice.
     */
    public function magicProperty(MagicPropertyRequest $request, Invoice $invoice): Invoice
    {
        return $invoice;
    }

    /**
     * FormRequest that compares the invoice owner with the signed-in user.
     */
    public function ownerComparison(OwnerComparisonRequest $request, Invoice $invoice): Invoice
    {
        return $invoice;
    }

    /**
     * Ability result passed to the response, never enforced.
     *
     * @return array<string, mixed>
     */
    public function unenforcedCan(Request $request, Invoice $invoice): array
    {
        $canEdit = $request->user()->can('update', $invoice);

        return ['invoice' => $invoice, 'can_edit' => $canEdit];
    }

    /**
     * Gate result discarded.
     */
    public function discardedGate(Invoice $invoice): Invoice
    {
        Gate::allows('update', $invoice);

        return $invoice;
    }

    /**
     * Ability result used as an if condition.
     */
    public function enforcedIf(Request $request, Invoice $invoice): Invoice
    {
        if (! $request->user()->can('update', $invoice)) {
            abort(403);
        }

        return $invoice;
    }

    /**
     * Ability result passed to abort_unless.
     */
    public function enforcedAbort(Request $request, Invoice $invoice): Invoice
    {
        abort_unless($request->user()->can('view', $invoice), 403);

        return $invoice;
    }

    /**
     * Gate response enforced with authorize().
     */
    public function inspectAuthorize(Invoice $invoice): Invoice
    {
        Gate::inspect('view', $invoice)->authorize();

        return $invoice;
    }

    /**
     * Ability check delegated to a helper that returns the verdict.
     */
    public function helperVerdict(Request $request, Invoice $invoice): Invoice
    {
        abort_unless($this->mayView($request, $invoice), 403);

        return $invoice;
    }

    /**
     * Write guarded only by a signed-in check.
     *
     * @return array<string, bool>
     */
    public function authCheckOnly(Request $request): array
    {
        if (Auth::check()) {
            return ['saved' => true];
        }

        return ['saved' => false];
    }

    /**
     * Delete by a raw id from the request.
     */
    public function destroyById(Request $request): int
    {
        return Invoice::destroy($request->input('id'));
    }

    /**
     * Update through an id constraint only.
     */
    public function updateById(Request $request): int
    {
        return Invoice::where('id', $request->input('id'))->update(['paid' => true]);
    }

    /**
     * Load by a raw id through firstWhere.
     */
    public function firstWhereId(Request $request): ?Invoice
    {
        return Invoice::firstWhere('id', $request->input('id'));
    }

    /**
     * Load a soft-deleting owned model by raw id.
     */
    public function softDeleted(Request $request): ?SoftInvoice
    {
        return SoftInvoice::findOrFail($request->input('id'));
    }

    /**
     * Scoped through Auth::id().
     */
    public function authIdScoped(Request $request): ?Invoice
    {
        return Invoice::where('user_id', Auth::id())->findOrFail($request->input('id'));
    }

    /**
     * The signed-in user appears in an unrelated constraint, so the lookup is not scoped.
     */
    public function userInOtherColumn(Request $request): ?Invoice
    {
        return Invoice::where('id', $request->input('id'))->where('status', $request->user()->status)->first();
    }

    /**
     * The owner column is compared with a value from the request, not the signed-in user.
     */
    public function ownerFromInput(Request $request): ?Invoice
    {
        return Invoice::where('user_id', $request->input('user_id'))->findOrFail($request->input('id'));
    }

    /**
     * Delete a table row by a raw id with no route model to match the table.
     */
    public function tableDelete(Request $request): int
    {
        return DB::table('invoices')->where('id', $request->input('id'))->delete();
    }

    /**
     * Delete a table row scoped through the signed-in user.
     */
    public function tableScopedDelete(Request $request): int
    {
        return DB::table('invoices')->where('user_id', Auth::id())->where('id', $request->input('id'))->delete();
    }

    /**
     * Scoped through a local variable that holds the signed-in user.
     */
    public function localUserScoped(Request $request): ?Invoice
    {
        $user = $request->user();

        return Invoice::where('user_id', $user->id)->findOrFail($request->input('id'));
    }

    /**
     * Scoped through Laravel's #[CurrentUser] parameter.
     */
    public function currentUserScoped(#[CurrentUser] User $owner, Request $request): ?Invoice
    {
        return Invoice::where('user_id', $owner->id)->findOrFail($request->input('id'));
    }

    /**
     * Helper that returns the gate verdict for the invoice.
     */
    private function mayView(Request $request, Invoice $invoice): bool
    {
        return $request->user()->can('view', $invoice);
    }
}
