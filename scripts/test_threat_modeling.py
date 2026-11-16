#!/usr/bin/env python3
"""离线回归威胁建模协议锚点与全局重排调度。

A 组是局部深度优先基线，B 组在每个区分性实验后按新证据全局重排。
消融组同样每轮全局选择，但不应用证据导致的优先级变化（no-op 重排）。
三组消费相同的合成候选、预定结果和预算；不访问网络或真实目标。

本脚本验证协议锚点和调度策略，不测真实模型，也不证明实际漏洞发现率。
A 组不是对旧模型行为的测量，而是用于复现局部 DFS 风险的对照策略。
逐步优先级轨迹用于核对收益是否只在证据驱动重排臂出现。
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PROTOCOL_ANCHORS = {
    'SKILL.md': (
        '轻量威胁建模与测试计划',
        '全局假设队列',
        '每完成一个区分性实验',
    ),
    'references/business-modeling.md': (
        '高价值滥用案例',
        '覆盖矩阵',
        '不创造资产或动作授权',
    ),
    'references/hunting-strategy.md': (
        '全局滥用案例队列',
        '每完成一个区分性实验',
        '未探索份额',
    ),
    'references/agent-execution.md': (
        '每完成一个区分性实验',
        '重新排序',
        '调度事件',
        '连续 2 次区分性实验为 0 增量',
    ),
    'references/state-and-evidence.md': (
        '测试计划',
        '调度事件',
        'decisions.jsonl',
    ),
    'references/checklist.md': (
        '威胁建模与计划',
        '调度与深度',
        '独立模型演练',
    ),
}


@dataclass(frozen=True)
class Outcome:
    """一次合成实验的预定结果。priority 仅用于调度，不代表命中概率。"""

    info_gain: int
    status: str = 'continue'  # continue / confirmed / not_reproduced
    priority_after: int | None = None
    boosts: tuple[tuple[str, int], ...] = ()


@dataclass
class Branch:
    name: str
    priority: int
    outcomes: tuple[Outcome, ...]
    high_value: bool = True
    attempts: int = 0
    zero_streak: int = 0
    terminal: str | None = None


@dataclass(frozen=True)
class Scenario:
    name: str
    budget: int
    max_branch_depth: int
    branches: tuple[Branch, ...]


@dataclass
class Result:
    trace: list[str] = field(default_factory=list)
    rankings: list[str] = field(default_factory=list)
    covered: set[str] = field(default_factory=set)
    high_value_covered: set[str] = field(default_factory=set)
    confirmed: set[str] = field(default_factory=set)
    zero_info: int = 0
    first_confirmed_at: int | None = None


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def check_protocol_anchors() -> None:
    for relative, anchors in PROTOCOL_ANCHORS.items():
        text = (ROOT / relative).read_text(encoding='utf-8')
        for anchor in anchors:
            require(anchor in text, f'{relative}: 缺少协议锚点「{anchor}」')
    print(f'协议锚点：{len(PROTOCOL_ANCHORS)}/{len(PROTOCOL_ANCHORS)} 个文件通过')


def simulate(scenario: Scenario, policy: str) -> Result:
    """模拟局部 DFS、no-op 重排或证据驱动的全局重排。"""
    require(policy in {'local_dfs', 'noop_rerank', 'global_rerank'}, f'未知策略：{policy}')
    branches = deepcopy(list(scenario.branches))
    by_name = {branch.name: branch for branch in branches}
    result = Result()
    active: Branch | None = None

    def eligible(branch: Branch) -> bool:
        limit = min(scenario.max_branch_depth, len(branch.outcomes))
        return branch.terminal is None and branch.attempts < limit

    for step in range(1, scenario.budget + 1):
        candidates = [branch for branch in branches if eligible(branch)]
        if not candidates:
            break
        if policy != 'local_dfs' or active is None or not eligible(active):
            # max 保持稳定：同优先级时选择原队列中更靠前者。
            # no-op 臂也每轮全局选择，只是不应用证据导致的优先级变化。
            active = max(candidates, key=lambda branch: branch.priority)

        branch = active
        outcome = branch.outcomes[branch.attempts]
        branch.attempts += 1
        result.trace.append(f'{branch.name}{branch.attempts}')
        result.covered.add(branch.name)
        if branch.high_value:
            result.high_value_covered.add(branch.name)
        if outcome.info_gain == 0:
            result.zero_info += 1
            branch.zero_streak += 1
        else:
            branch.zero_streak = 0
        if policy != 'noop_rerank':
            if outcome.priority_after is not None:
                branch.priority = outcome.priority_after
            for target, delta in outcome.boosts:
                by_name[target].priority += delta
        if policy == 'global_rerank' and branch.zero_streak >= 2 and outcome.status == 'continue':
            # 协议硬止损：连续 2 次 0 增量强制降档，防止事后合理化死磕
            branch.priority = min(branch.priority, 0)
        if outcome.status != 'continue':
            branch.terminal = outcome.status
        if outcome.status == 'confirmed':
            result.confirmed.add(branch.name)
            if result.first_confirmed_at is None:
                result.first_confirmed_at = step

        ranking = ','.join(
            f'{item.name}={item.priority}/{item.terminal or "d" + str(item.attempts)}'
            for item in branches
        )
        result.rankings.append(f'{step}:{result.trace[-1]}[{ranking}]')
        if policy == 'local_dfs' and not eligible(branch):
            active = None
        # 其余两臂故意不保留 active；下一轮必须重新比较全局队列。

    total_high_value = {b.name for b in scenario.branches if b.high_value}
    require(result.high_value_covered <= total_high_value, '覆盖指标越界')
    require(len(result.trace) <= scenario.budget, '共享预算被突破')
    require(all(b.attempts <= scenario.max_branch_depth for b in branches), '分支深度上限被突破')
    return result


def scenarios() -> tuple[Scenario, ...]:
    return (
        Scenario(
            name='1. 首条高分分支持续无信息，其他入口有独立结论',
            budget=4,
            max_branch_depth=4,
            branches=(
                Branch('A', 90, (
                    Outcome(1, priority_after=20),
                    Outcome(0, priority_after=20),
                    Outcome(0, priority_after=20),
                    Outcome(0, priority_after=20),
                )),
                Branch('B', 80, (Outcome(2, status='confirmed'),)),
                Branch('C', 70, (Outcome(1, status='not_reproduced'),), high_value=False),
            ),
        ),
        Scenario(
            name='2. 当前分支保持全局最优，不应为广度机械切换',
            budget=3,
            max_branch_depth=4,
            branches=(
                Branch('A', 90, (
                    Outcome(2, priority_after=95),
                    Outcome(2, status='confirmed'),
                )),
                Branch('B', 80, (Outcome(2, status='confirmed'),)),
                Branch('C', 70, (Outcome(1, status='not_reproduced'),), high_value=False),
            ),
        ),
        Scenario(
            name='3. 当前实验揭示共享异步边界，提升另一分支优先级',
            budget=5,
            max_branch_depth=3,
            branches=(
                Branch('A', 90, (
                    Outcome(2, priority_after=40, boosts=(('B', 50),)),
                    Outcome(0, priority_after=40),
                    Outcome(0, status='not_reproduced'),
                ), high_value=False),
                Branch('B', 70, (
                    Outcome(1, priority_after=110),
                    Outcome(2, status='confirmed'),
                )),
                Branch('C', 80, (Outcome(1, status='not_reproduced'),), high_value=False),
            ),
        ),
        Scenario(
            name='4. 连续两次零增量强制降档，防止主观高估死磕',
            budget=4,
            max_branch_depth=4,
            branches=(
                Branch('A', 90, (
                    Outcome(0, priority_after=88),
                    Outcome(0, priority_after=86),
                    Outcome(0, priority_after=84),
                    Outcome(0, status='not_reproduced'),
                )),
                Branch('B', 80, (Outcome(2, status='confirmed'),)),
                Branch('C', 70, (Outcome(1, status='not_reproduced'),), high_value=False),
            ),
        ),
    )


def validate_ab(name: str, baseline: Result, noop: Result, reranked: Result) -> None:
    if name.startswith('1.'):
        require(baseline.trace == ['A1', 'A2', 'A3', 'A4'], '场景1基线未复现局部DFS')
        require(noop.trace == baseline.trace, '场景1 no-op重排未隔离出相同结果')
        require(reranked.trace == ['A1', 'B1', 'C1', 'A2'], '场景1重排顺序不符合全局优先级')
        require(len(reranked.covered) > len(noop.covered), '场景1相对消融臂覆盖未改善')
        require(reranked.first_confirmed_at == 2, '场景1未在第2个实验确认B')
        require(noop.first_confirmed_at is None, '场景1 no-op重排不应确认')
        require(reranked.zero_info < noop.zero_info, '场景1相对消融臂零信息实验未减少')
    elif name.startswith('2.'):
        require(reranked.trace == noop.trace == baseline.trace == ['A1', 'A2', 'B1'], '场景2发生机械切换')
        require(reranked.first_confirmed_at == noop.first_confirmed_at == 2, '场景2确认被延迟')
        require(reranked.confirmed == noop.confirmed == {'A', 'B'}, '场景2确认结果不一致')
    elif name.startswith('3.'):
        require(baseline.trace == ['A1', 'A2', 'A3', 'B1', 'B2'], '场景3基线顺序异常')
        require(noop.trace == ['A1', 'A2', 'A3', 'C1', 'B1'], '场景3 no-op重排隔离结果异常')
        require(noop.first_confirmed_at is None, '场景3 no-op重排不应提前确认')
        require(reranked.trace == ['A1', 'B1', 'B2', 'C1', 'A2'], '场景3未消费共享边界新证据')
        require(reranked.first_confirmed_at == 3, '场景3重排未提前确认')
        require(baseline.first_confirmed_at == 5, '场景3基线确认位置异常')
        require(len(reranked.covered) == len(noop.covered) == 3, '场景3两臂应覆盖相同分支，改善仅限确认时机')
    elif name.startswith('4.'):
        require(baseline.trace == ['A1', 'A2', 'A3', 'A4'], '场景4基线未复现局部DFS')
        require(noop.trace == baseline.trace, '场景4 no-op重排未隔离出相同结果')
        require(reranked.trace == ['A1', 'A2', 'B1', 'C1'], '场景4未在连续两次零增量后强制降档')
        require(reranked.first_confirmed_at == 3, '场景4未在第3步确认B')
        require(noop.first_confirmed_at is None, '场景4 no-op重排不应确认')
        require(reranked.zero_info < noop.zero_info, '场景4零信息实验未减少')
    else:
        raise RuntimeError(f'未知场景：{name}')


def print_result(policy: str, result: Result, high_value_total: int) -> None:
    confirmed_at = result.first_confirmed_at if result.first_confirmed_at is not None else '未确认'
    print(f'  {policy}: 实验={len(result.trace)}，覆盖={len(result.covered)}，'
          f'高价值覆盖={len(result.high_value_covered)}/{high_value_total}，'
          f'确认={len(result.confirmed)}，首次确认={confirmed_at}，'
          f'零信息={result.zero_info}，序列={",".join(result.trace)}')
    for ranking in result.rankings:
        print(f'    {ranking}')


def main() -> int:
    try:
        check_protocol_anchors()
        for scenario in scenarios():
            baseline = simulate(scenario, 'local_dfs')
            noop = simulate(scenario, 'noop_rerank')
            reranked = simulate(scenario, 'global_rerank')
            validate_ab(scenario.name, baseline, noop, reranked)
            high_value_total = sum(branch.high_value for branch in scenario.branches)
            print(scenario.name)
            print_result('A/局部DFS', baseline, high_value_total)
            print_result('消融/no-op重排', noop, high_value_total)
            print_result('B/证据驱动全局重排', reranked, high_value_total)
    except (OSError, RuntimeError) as exc:
        print(f'FAIL: {exc}')
        return 1
    print('全部协议锚点、A/B 场景与 no-op 消融断言通过。')
    print('限制：这是合成调度回归，不是实际模型或真实目标的行为评测。')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
