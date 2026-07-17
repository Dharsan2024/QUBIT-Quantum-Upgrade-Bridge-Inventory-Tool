
import { useQuery } from "@tanstack/react-query";
import { fetchAssets } from "../api/client";
import { useUiStore } from "../stores/ui";
import { AssetTable } from "../components/AssetTable";
import { Shield, RefreshCw } from "lucide-react";

export function Inventory() {
  const projectId = useUiStore((state) => state.projectId);
  const scanId = useUiStore((state) => state.scanId);

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["assets", projectId, scanId],
    queryFn: () => fetchAssets(projectId, scanId),
  });

  return (
    <div className="flex flex-col gap-6 w-full max-w-7xl mx-auto py-8 px-4">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-gray-900 flex items-center gap-3">
            <Shield className="w-8 h-8 text-indigo-600" />
            Cryptographic Inventory
          </h1>
          <p className="mt-2 text-sm text-gray-600">
            Discovered cryptographic assets across {projectId} (Scan: {scanId || "Latest"})
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md shadow-sm hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </header>

      <main>
        {isLoading && (
          <div className="flex items-center justify-center p-12 text-gray-500">
            Loading assets...
          </div>
        )}
        
        {isError && (
          <div className="p-4 bg-red-50 border border-red-200 rounded-md text-red-700">
            Error loading inventory: {error instanceof Error ? error.message : "Unknown error"}
          </div>
        )}

        {data && (
          <div className="space-y-4">
            <div className="flex items-center justify-between text-sm text-gray-500">
              <span>Showing {data.items.length} of {data.total} assets</span>
            </div>
            <AssetTable data={data.items} />
          </div>
        )}
      </main>
    </div>
  );
}
