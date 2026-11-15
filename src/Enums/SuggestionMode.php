<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Enums;

enum SuggestionMode: string
{
    case Patch = 'patch';
    case Hint = 'hint';
}
