import React from "react";

const FindingsTable = ({ columns, data, emptyMessage = "Aucun résultat." }) => {
  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center py-12 text-neutral-500 text-sm">
        {emptyMessage}
      </div>
    );
  }

  return (
    <div className="w-full overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[#2e2e2e]">
            {columns.map((col) => (
              <th
                key={col.key}
                className="text-left py-3 px-4 text-xs font-mono uppercase tracking-widest text-neutral-500 whitespace-nowrap"
              >
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, idx) => (
            <tr
              key={row.id || idx}
              className="border-b border-[#222222] table-row-hover transition-colors"
            >
              {columns.map((col) => (
                <td key={col.key} className="py-3 px-4 text-neutral-300 align-top">
                  {col.render ? col.render(row[col.key], row) : row[col.key]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default FindingsTable;
