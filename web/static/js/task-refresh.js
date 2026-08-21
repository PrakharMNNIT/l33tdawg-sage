const TASK_LOAD_ERROR = 'SAGE could not load your task list. Your tasks are still safe; try again.';

// Refresh the authoritative task snapshot without coupling background refreshes
// to the board's loading surface. Failures always reject so reconciliation can
// never mistake an unreadable snapshot for a confirmed empty task list.
export async function refreshTaskSnapshot({ fetcher, settlingIDs = new Set(), silent = false, isCurrent = () => true, setTasks, setDomains, setError }) {
  let data;
  try {
    data = await fetcher({ all: true, limit: 500 });
  } catch (error) {
    // An older request must not replace state from a newer success or failure.
    if (isCurrent() && !silent) setError(TASK_LOAD_ERROR);
    throw error;
  }
  if (!isCurrent()) return undefined;
  const items = Array.isArray(data?.tasks) ? data.tasks : [];
  const visible = settlingIDs.size
    ? items.filter(task => !settlingIDs.has(task.memory_id))
    : items;
  setTasks(visible);
  setDomains([...new Set(items.map(task => task.domain_tag).filter(Boolean))].sort());
  // A successful authoritative refresh recovers a prior visible load error,
  // even when the recovery was triggered silently by SSE.
  setError(null);
  return items;
}
