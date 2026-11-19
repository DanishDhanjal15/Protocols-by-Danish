export default function Loading() {
  return (
    <div className="max-w-[1800px] w-full mx-auto p-4 flex flex-col gap-3" aria-busy="true" aria-label="Loading lesson">
      <div className="h-10 w-72 rounded-lg bg-panel-2 animate-pulse" />
      <div className="card stage-bg w-full animate-pulse" style={{ aspectRatio: "1000 / 460", maxHeight: "62vh" }} />
      <div className="grid gap-3 xl:grid-cols-[5fr_7fr]">
        <div className="card h-64 animate-pulse" />
        <div className="card h-64 animate-pulse" />
      </div>
    </div>
  );
}
