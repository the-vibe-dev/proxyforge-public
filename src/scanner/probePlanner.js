"use strict";
// Plans which checks to run against which insertion points.
Object.defineProperty(exports, "__esModule", { value: true });
exports.planProbes = planProbes;
const payloadMutationEngine_1 = require("./payloadMutationEngine");
const FAMILY_TO_CHECK = {
    'sql-injection': 'sql-injection',
    'xss-reflected': 'xss-reflected',
    'xss-oracle': 'xss-oracle',
    'ssti': 'ssti',
    'lfi-traversal': 'lfi-traversal',
    'command-injection': 'command-injection',
    'ssrf': 'ssrf',
    'ssrf-oast': 'ssrf-oast',
    'open-redirect': 'open-redirect',
    'xxe': 'xxe-file',
    'xxe-oast': 'xxe-oast',
    'nosql-injection': 'nosql-injection',
    'xpath-injection': 'xpath-injection',
    'ldap-injection': 'ldap-injection',
    'expression-language-injection': 'expression-language-injection',
    'csv-formula-injection': 'csv-formula-injection',
};
function priorityForFamily(family) {
    const high = ['command-injection', 'sql-injection', 'ssrf-oast', 'xxe-oast'];
    const medium = ['xss-reflected', 'ssti', 'lfi-traversal', 'ssrf', 'open-redirect'];
    if (high.includes(family))
        return 1;
    if (medium.includes(family))
        return 2;
    return 3;
}
function planProbes(insertionPoints, requestedCheckIds, budget) {
    const checkSet = new Set(requestedCheckIds);
    const plans = [];
    for (const ip of insertionPoints) {
        const families = (0, payloadMutationEngine_1.familiesForInsertionPoint)(ip.kind);
        for (const family of families) {
            const checkId = FAMILY_TO_CHECK[family];
            if (!checkId)
                continue;
            if (checkSet.size > 0 && !checkSet.has(checkId))
                continue;
            if (!budget.allowOast && (family === 'ssrf-oast' || family === 'xxe-oast' || family === 'command-injection-blind-oast'))
                continue;
            plans.push({
                insertionPoint: ip,
                checkId,
                family,
                priority: priorityForFamily(family),
            });
        }
    }
    plans.sort((a, b) => a.priority - b.priority);
    // Cap total plans to avoid runaway scans.
    const maxPlans = Math.min(plans.length, budget.maxRequests * 2);
    return plans.slice(0, maxPlans);
}
