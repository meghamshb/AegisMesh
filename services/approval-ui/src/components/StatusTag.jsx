export function StatusTag({ status }) {
  return <span className={`status-tag ${status}`}>[{String(status).toUpperCase()}]</span>
}
