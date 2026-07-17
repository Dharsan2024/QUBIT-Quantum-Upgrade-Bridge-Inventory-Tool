import {
  useReactTable,
  getCoreRowModel,
  flexRender,
} from "@tanstack/react-table";
import type { ColumnDef } from "@tanstack/react-table";
import type { CryptoAsset } from "../api/types";
import { ShieldAlert, ShieldCheck } from "lucide-react";


const columns: ColumnDef<CryptoAsset>[] = [
  {
    accessorKey: "algorithm",
    header: "Algorithm",
    cell: (info) => <span className="font-mono font-medium">{info.getValue() as string}</span>,
  },
  {
    accessorKey: "usage_context",
    header: "Context",
  },
  {
    accessorKey: "quantum_vulnerable.vulnerable",
    header: "Status",
    cell: (info) => {
      const vulnerable = info.getValue() as boolean;
      return vulnerable ? (
        <span className="flex items-center text-red-600 gap-1.5">
          <ShieldAlert className="w-4 h-4" /> Vulnerable
        </span>
      ) : (
        <span className="flex items-center text-green-600 gap-1.5">
          <ShieldCheck className="w-4 h-4" /> Safe
        </span>
      );
    },
  },
  {
    id: "location",
    header: "Location",
    cell: ({ row }) => {
      const loc = row.original.location;
      if (loc.file_path) {
        return <span className="text-gray-500 font-mono text-sm">{loc.file_path}{loc.line ? `:${loc.line}` : ''}</span>;
      }
      if (loc.host) {
        return <span className="text-gray-500 font-mono text-sm">{loc.host}:{loc.service || ''}</span>;
      }
      return <span className="text-gray-400 italic">Unknown</span>;
    }
  },
  {
    accessorKey: "risk.priority_rank",
    header: "Priority Rank",
    cell: (info) => {
      const val = info.getValue();
      return val ? <span className="font-bold">{val as number}</span> : <span className="text-gray-300">-</span>;
    }
  }
];

export function AssetTable({ data }: { data: CryptoAsset[] }) {
  const table = useReactTable({
    data,
    columns,
    getCoreRowModel: getCoreRowModel(),
  });

  return (
    <div className="overflow-x-auto rounded-lg border border-gray-200">
      <table className="min-w-full divide-y divide-gray-200 text-sm">
        <thead className="bg-gray-50">
          {table.getHeaderGroups().map((headerGroup) => (
            <tr key={headerGroup.id}>
              {headerGroup.headers.map((header) => (
                <th
                  key={header.id}
                  className="px-6 py-3 text-left font-semibold text-gray-900"
                >
                  {header.isPlaceholder
                    ? null
                    : flexRender(
                        header.column.columnDef.header,
                        header.getContext()
                      )}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody className="divide-y divide-gray-200 bg-white">
          {table.getRowModel().rows.map((row) => (
            <tr key={row.id} className="hover:bg-gray-50">
              {row.getVisibleCells().map((cell) => (
                <td key={cell.id} className="px-6 py-4 whitespace-nowrap">
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </td>
              ))}
            </tr>
          ))}
          {data.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="px-6 py-8 text-center text-gray-500">
                No crypto assets found.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
