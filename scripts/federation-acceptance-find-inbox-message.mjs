import { pathToFileURL } from 'node:url';

export function findInboxMessage(inbox, { intent, payload, senderAgent, sourceChain }) {
  const items = Array.isArray(inbox?.items) ? inbox.items : [];
  return items.find(item =>
    typeof item?.message_id === 'string' && item.message_id !== '' &&
    item.intent === intent &&
    item.payload === payload &&
    item.sender_agent === senderAgent &&
    item.source_chain === sourceChain
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [inboxJSON, intent, payload, senderAgent, sourceChain] = process.argv.slice(2);
  const item = findInboxMessage(JSON.parse(inboxJSON), {
    intent,
    payload,
    senderAgent,
    sourceChain,
  });
  if (item) process.stdout.write(item.message_id);
}
