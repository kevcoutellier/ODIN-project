/**
 * MCTS + LLM Hierarchical Planner
 *
 * Monte Carlo Tree Search adapted for agent planning:
 * - Each node = a world state after an action
 * - Each edge = an action (tool call, reasoning step, delegation)
 * - LLM provides the EXPANSION heuristic (which actions to try)
 * - Simulation uses lightweight prediction (not full LLM calls)
 * - Backpropagation updates action-value estimates
 *
 * Hierarchical: High-level goals decompose into sub-goals,
 * each sub-goal has its own MCTS tree. Top-level selects
 * which sub-tree to explore based on UCB1.
 *
 * This replaces greedy single-step planning with lookahead.
 */

import { randomUUID } from 'node:crypto';

// ─── Types ───

export interface MCTSConfig {
  /** Max iterations per planning call. Default: 100 */
  maxIterations: number;
  /** Exploration constant (UCB1). Default: 1.414 (sqrt(2)) */
  explorationConstant: number;
  /** Max tree depth. Default: 8 */
  maxDepth: number;
  /** Discount factor for future rewards. Default: 0.95 */
  discountFactor: number;
  /** Max children per node (action branching factor). Default: 5 */
  maxBranching: number;
  /** Simulation rollout depth. Default: 3 */
  rolloutDepth: number;
}

const DEFAULT_CONFIG: MCTSConfig = {
  maxIterations: 100,
  explorationConstant: Math.SQRT2,
  maxDepth: 8,
  discountFactor: 0.95,
  maxBranching: 5,
  rolloutDepth: 3,
};

export interface MCTSState {
  description: string;
  entities: Array<{ name: string; type: string }>;
  goals: Array<{ description: string; achieved: boolean; priority: number }>;
  resources: Record<string, number>; // e.g., { tokens: 1000, time: 300 }
  constraints: string[];
}

export interface MCTSAction {
  id: string;
  type: 'tool_call' | 'reasoning' | 'delegation' | 'subgoal';
  name: string;
  args?: Record<string, unknown>;
  description: string;
  estimatedCost: number; // Resource cost estimate
  preconditions: string[];
}

export interface MCTSNode {
  id: string;
  state: MCTSState;
  action: MCTSAction | null; // Action that led to this state (null for root)
  parent: MCTSNode | null;
  children: MCTSNode[];
  visits: number;
  totalReward: number;
  depth: number;
  isTerminal: boolean;
  isExpanded: boolean;
}

export interface MCTSPlan {
  id: string;
  goal: string;
  actions: MCTSAction[];
  expectedReward: number;
  confidence: number;
  treeStats: {
    totalNodes: number;
    totalIterations: number;
    maxDepthReached: number;
    avgBranchingFactor: number;
  };
  createdAt: number;
}

/** Hierarchy: a goal decomposed into sub-goals, each with its own MCTS tree */
export interface HierarchicalGoal {
  id: string;
  description: string;
  priority: number;
  subGoals: HierarchicalGoal[];
  plan: MCTSPlan | null;
  status: 'pending' | 'planning' | 'executing' | 'completed' | 'failed';
}

// ─── Action Generator (pluggable — can be LLM-backed) ───

export type ActionGenerator = (state: MCTSState) => MCTSAction[];
export type RewardEstimator = (state: MCTSState, action: MCTSAction) => number;
export type StateTransition = (state: MCTSState, action: MCTSAction) => MCTSState;

// ─── Default heuristics (non-LLM, rule-based) ───

function defaultActionGenerator(state: MCTSState): MCTSAction[] {
  const actions: MCTSAction[] = [];
  const unachieved = state.goals.filter(g => !g.achieved);

  for (const goal of unachieved.slice(0, 3)) {
    // Suggest tool-based actions for each unachieved goal
    actions.push({
      id: randomUUID(),
      type: 'reasoning',
      name: `analyze_${goal.description.slice(0, 20).replace(/\s+/g, '_')}`,
      description: `Analyze requirements for: ${goal.description}`,
      estimatedCost: 1,
      preconditions: [],
    });

    actions.push({
      id: randomUUID(),
      type: 'tool_call',
      name: 'execute_toward_goal',
      args: { goal: goal.description },
      description: `Take action toward: ${goal.description}`,
      estimatedCost: 5,
      preconditions: [],
    });
  }

  // Always offer a delegation option if there are multiple goals
  if (unachieved.length > 1) {
    actions.push({
      id: randomUUID(),
      type: 'delegation',
      name: 'delegate_subgoal',
      description: `Delegate a sub-goal to a sub-agent`,
      estimatedCost: 10,
      preconditions: [],
    });
  }

  return actions;
}

function defaultRewardEstimator(state: MCTSState, action: MCTSAction): number {
  const achievedRatio = state.goals.filter(g => g.achieved).length / Math.max(1, state.goals.length);
  const priorityBonus = state.goals
    .filter(g => g.achieved)
    .reduce((sum, g) => sum + g.priority, 0) / Math.max(1, state.goals.length);

  // Penalize high-cost actions
  const costPenalty = action.estimatedCost / 20;

  return achievedRatio * 0.5 + priorityBonus * 0.3 - costPenalty * 0.2;
}

function defaultStateTransition(state: MCTSState, action: MCTSAction): MCTSState {
  const newState: MCTSState = {
    ...state,
    description: `After: ${action.description}`,
    goals: state.goals.map(g => ({ ...g })),
    resources: { ...state.resources },
    entities: [...state.entities],
    constraints: [...state.constraints],
  };

  // Simulate resource consumption
  if (newState.resources.tokens !== undefined) {
    newState.resources.tokens = Math.max(0, newState.resources.tokens - action.estimatedCost * 100);
  }

  // Optimistically mark some goals as achieved based on action type
  if (action.type === 'tool_call' || action.type === 'delegation') {
    const unachieved = newState.goals.filter(g => !g.achieved);
    if (unachieved.length > 0) {
      // 50% chance of achieving the lowest-priority unachieved goal
      const target = unachieved.sort((a, b) => a.priority - b.priority)[0];
      if (Math.random() > 0.5) target.achieved = true;
    }
  }

  return newState;
}

// ─── MCTS Engine ───

export class MCTSPlanner {
  private config: MCTSConfig;
  private generateActions: ActionGenerator;
  private estimateReward: RewardEstimator;
  private transition: StateTransition;
  private nodeCount = 0;

  constructor(
    config: Partial<MCTSConfig> = {},
    actionGenerator?: ActionGenerator,
    rewardEstimator?: RewardEstimator,
    stateTransition?: StateTransition,
  ) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.generateActions = actionGenerator ?? defaultActionGenerator;
    this.estimateReward = rewardEstimator ?? defaultRewardEstimator;
    this.transition = stateTransition ?? defaultStateTransition;
  }

  /**
   * Run MCTS planning from the given state toward the goal.
   */
  plan(initialState: MCTSState, goal: string): MCTSPlan {
    this.nodeCount = 0;
    const root = this.createNode(initialState, null, null, 0);
    let maxDepthReached = 0;

    for (let i = 0; i < this.config.maxIterations; i++) {
      // 1. SELECT: Walk down the tree using UCB1
      const selected = this.select(root);

      // 2. EXPAND: Add a new child node
      const expanded = this.expand(selected);
      if (!expanded) continue;

      if (expanded.depth > maxDepthReached) maxDepthReached = expanded.depth;

      // 3. SIMULATE: Rollout from the new node
      const reward = this.simulate(expanded);

      // 4. BACKPROPAGATE: Update values up the tree
      this.backpropagate(expanded, reward);
    }

    // Extract the best path from root
    const bestPath = this.extractBestPath(root);

    // Compute stats
    const allNodes = this.collectNodes(root);
    const branchingFactors = allNodes
      .filter(n => n.children.length > 0)
      .map(n => n.children.length);
    const avgBranching = branchingFactors.length > 0
      ? branchingFactors.reduce((a, b) => a + b, 0) / branchingFactors.length
      : 0;

    return {
      id: `mcts-plan-${Date.now()}`,
      goal,
      actions: bestPath.map(n => n.action!).filter(Boolean),
      expectedReward: root.visits > 0 ? root.totalReward / root.visits : 0,
      confidence: this.computeConfidence(root),
      treeStats: {
        totalNodes: this.nodeCount,
        totalIterations: this.config.maxIterations,
        maxDepthReached,
        avgBranchingFactor: Math.round(avgBranching * 100) / 100,
      },
      createdAt: Date.now(),
    };
  }

  // ─── MCTS Core Operations ───

  private select(node: MCTSNode): MCTSNode {
    let current = node;
    while (current.isExpanded && current.children.length > 0 && !current.isTerminal) {
      current = this.bestUCB1Child(current);
    }
    return current;
  }

  private expand(node: MCTSNode): MCTSNode | null {
    if (node.isTerminal || node.depth >= this.config.maxDepth) return null;

    if (!node.isExpanded) {
      // Generate possible actions
      const actions = this.generateActions(node.state).slice(0, this.config.maxBranching);

      for (const action of actions) {
        const newState = this.transition(node.state, action);
        const isTerminal = newState.goals.every(g => g.achieved) || node.depth + 1 >= this.config.maxDepth;
        const child = this.createNode(newState, action, node, node.depth + 1);
        child.isTerminal = isTerminal;
        node.children.push(child);
      }
      node.isExpanded = true;
    }

    // Return an unvisited child, or a random one if all visited
    const unvisited = node.children.filter(c => c.visits === 0);
    if (unvisited.length > 0) {
      return unvisited[Math.floor(Math.random() * unvisited.length)];
    }

    return node.children.length > 0
      ? node.children[Math.floor(Math.random() * node.children.length)]
      : null;
  }

  private simulate(node: MCTSNode): number {
    let state = { ...node.state, goals: node.state.goals.map(g => ({ ...g })) };
    let totalReward = 0;
    let discount = 1.0;

    for (let d = 0; d < this.config.rolloutDepth; d++) {
      const actions = this.generateActions(state);
      if (actions.length === 0) break;

      // Random rollout action
      const action = actions[Math.floor(Math.random() * actions.length)];
      const reward = this.estimateReward(state, action);
      totalReward += discount * reward;
      discount *= this.config.discountFactor;

      state = this.transition(state, action);

      // Check terminal
      if (state.goals.every(g => g.achieved)) {
        totalReward += discount * 1.0; // Bonus for achieving all goals
        break;
      }
    }

    return totalReward;
  }

  private backpropagate(node: MCTSNode, reward: number): void {
    let current: MCTSNode | null = node;
    while (current !== null) {
      current.visits++;
      current.totalReward += reward;
      current = current.parent;
    }
  }

  // ─── Helpers ───

  private bestUCB1Child(node: MCTSNode): MCTSNode {
    let bestScore = -Infinity;
    let bestChild = node.children[0];
    const logN = Math.log(node.visits);

    for (const child of node.children) {
      const exploitation = child.visits > 0 ? child.totalReward / child.visits : 0;
      const exploration = child.visits > 0
        ? this.config.explorationConstant * Math.sqrt(logN / child.visits)
        : Infinity; // Unvisited nodes get infinite priority
      const score = exploitation + exploration;

      if (score > bestScore) {
        bestScore = score;
        bestChild = child;
      }
    }

    return bestChild;
  }

  private extractBestPath(root: MCTSNode): MCTSNode[] {
    const path: MCTSNode[] = [];
    let current = root;

    while (current.children.length > 0) {
      // Pick child with highest average reward (exploitation only)
      let best = current.children[0];
      let bestAvg = -Infinity;
      for (const child of current.children) {
        const avg = child.visits > 0 ? child.totalReward / child.visits : -Infinity;
        if (avg > bestAvg) {
          bestAvg = avg;
          best = child;
        }
      }
      path.push(best);
      current = best;
    }

    return path;
  }

  private computeConfidence(root: MCTSNode): number {
    if (root.visits === 0) return 0;
    const avgReward = root.totalReward / root.visits;
    // Normalize to 0-1 range (rewards are roughly -1 to 1)
    return Math.max(0, Math.min(1, (avgReward + 1) / 2));
  }

  private createNode(state: MCTSState, action: MCTSAction | null, parent: MCTSNode | null, depth: number): MCTSNode {
    this.nodeCount++;
    return {
      id: `node-${this.nodeCount}`,
      state,
      action,
      parent,
      children: [],
      visits: 0,
      totalReward: 0,
      depth,
      isTerminal: false,
      isExpanded: false,
    };
  }

  private collectNodes(node: MCTSNode): MCTSNode[] {
    const nodes: MCTSNode[] = [node];
    for (const child of node.children) {
      nodes.push(...this.collectNodes(child));
    }
    return nodes;
  }
}

// ─── Hierarchical Planner ───

export class HierarchicalPlanner {
  private goals: HierarchicalGoal[] = [];
  private mcts: MCTSPlanner;
  private planHistory: MCTSPlan[] = [];
  private maxHistory = 50;

  constructor(
    mctsConfig?: Partial<MCTSConfig>,
    actionGenerator?: ActionGenerator,
    rewardEstimator?: RewardEstimator,
    stateTransition?: StateTransition,
  ) {
    this.mcts = new MCTSPlanner(mctsConfig, actionGenerator, rewardEstimator, stateTransition);
  }

  /**
   * Set a custom MCTS planner (e.g., with LLM-backed action generation).
   */
  setPlanner(mcts: MCTSPlanner): void {
    this.mcts = mcts;
  }

  /**
   * Add a top-level goal, optionally with sub-goals.
   */
  addGoal(description: string, priority: number, subGoalDescriptions: string[] = []): HierarchicalGoal {
    const goal: HierarchicalGoal = {
      id: randomUUID(),
      description,
      priority,
      subGoals: subGoalDescriptions.map(sg => ({
        id: randomUUID(),
        description: sg,
        priority: priority * 0.8,
        subGoals: [],
        plan: null,
        status: 'pending',
      })),
      plan: null,
      status: 'pending',
    };
    this.goals.push(goal);
    this.goals.sort((a, b) => b.priority - a.priority);
    return goal;
  }

  /**
   * Plan the next goal (highest priority unplanned).
   */
  planNext(currentState: MCTSState): MCTSPlan | null {
    // Find highest-priority pending goal
    const pending = this.findPendingGoal(this.goals);
    if (!pending) return null;

    pending.status = 'planning';

    // If goal has sub-goals, plan the first pending sub-goal
    const subPending = pending.subGoals.find(sg => sg.status === 'pending');
    const target = subPending ?? pending;

    // Build state with the target goal
    const planState: MCTSState = {
      ...currentState,
      goals: [
        { description: target.description, achieved: false, priority: target.priority },
        ...currentState.goals,
      ],
    };

    const plan = this.mcts.plan(planState, target.description);
    target.plan = plan;
    target.status = 'executing';

    this.planHistory.push(plan);
    if (this.planHistory.length > this.maxHistory) {
      this.planHistory = this.planHistory.slice(-this.maxHistory);
    }

    return plan;
  }

  /**
   * Mark a goal as completed.
   */
  completeGoal(goalId: string): void {
    const goal = this.findGoalById(goalId, this.goals);
    if (goal) {
      goal.status = 'completed';
      // Check if parent is complete (all sub-goals done)
      this.propagateCompletion(this.goals);
    }
  }

  /**
   * Mark a goal as failed.
   */
  failGoal(goalId: string, reason?: string): void {
    const goal = this.findGoalById(goalId, this.goals);
    if (goal) goal.status = 'failed';
  }

  /**
   * Get the prompt section for active plans.
   */
  getPlanningPrompt(): string {
    const activeGoals = this.goals.filter(g => g.status !== 'completed' && g.status !== 'failed');
    if (activeGoals.length === 0) return '';

    const parts = ['## Hierarchical Plan', ''];

    for (const goal of activeGoals) {
      const icon = goal.status === 'executing' ? '►' : '○';
      parts.push(`${icon} **${goal.description}** [P${(goal.priority * 10).toFixed(0)}] — ${goal.status}`);

      if (goal.plan) {
        parts.push(`  Plan confidence: ${(goal.plan.confidence * 100).toFixed(0)}%`);
        for (const action of goal.plan.actions.slice(0, 5)) {
          parts.push(`    → ${action.name}: ${action.description}`);
        }
      }

      for (const sub of goal.subGoals) {
        const subIcon = sub.status === 'completed' ? '✓' : sub.status === 'executing' ? '►' : '○';
        parts.push(`  ${subIcon} ${sub.description} — ${sub.status}`);
      }
    }

    return parts.join('\n');
  }

  getGoals(): HierarchicalGoal[] { return this.goals; }
  getPlanHistory(): MCTSPlan[] { return this.planHistory; }

  getStats(): { totalGoals: number; completed: number; pending: number; executing: number; failed: number } {
    const all = this.flattenGoals(this.goals);
    return {
      totalGoals: all.length,
      completed: all.filter(g => g.status === 'completed').length,
      pending: all.filter(g => g.status === 'pending').length,
      executing: all.filter(g => g.status === 'executing' || g.status === 'planning').length,
      failed: all.filter(g => g.status === 'failed').length,
    };
  }

  // ─── Helpers ───

  private findPendingGoal(goals: HierarchicalGoal[]): HierarchicalGoal | null {
    for (const g of goals) {
      if (g.status === 'pending') return g;
      const sub = this.findPendingGoal(g.subGoals);
      if (sub) return sub;
    }
    return null;
  }

  private findGoalById(id: string, goals: HierarchicalGoal[]): HierarchicalGoal | null {
    for (const g of goals) {
      if (g.id === id) return g;
      const sub = this.findGoalById(id, g.subGoals);
      if (sub) return sub;
    }
    return null;
  }

  private propagateCompletion(goals: HierarchicalGoal[]): void {
    for (const g of goals) {
      if (g.subGoals.length > 0 && g.subGoals.every(sg => sg.status === 'completed')) {
        g.status = 'completed';
      }
      this.propagateCompletion(g.subGoals);
    }
  }

  private flattenGoals(goals: HierarchicalGoal[]): HierarchicalGoal[] {
    const result: HierarchicalGoal[] = [];
    for (const g of goals) {
      result.push(g);
      result.push(...this.flattenGoals(g.subGoals));
    }
    return result;
  }
}
