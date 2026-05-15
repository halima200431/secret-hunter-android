import React, { useRef, useState } from "react";
import { UploadCloud, FileCode, X, AlertCircle } from "lucide-react";

const UploadCard = ({ onFileSelect, selectedFile, error }) => {
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);

  const handleDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) onFileSelect(file);
  };

  const handleChange = (e) => {
    const file = e.target.files[0];
    if (file) onFileSelect(file);
  };

  return (
    <div className="flex flex-col gap-3">
      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-all
          ${dragging
            ? "border-accent bg-accent/5"
            : error
            ? "border-risk-critical/50 bg-risk-critical/5"
            : "border-[#333333] bg-[#1a1a1a] hover:border-[#444444] hover:bg-[#1e1e1e]"
          }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".apk"
          className="hidden"
          onChange={handleChange}
        />

        {selectedFile ? (
          <div className="flex flex-col items-center gap-3">
            <div className="w-12 h-12 rounded-xl bg-accent/10 flex items-center justify-center">
              <FileCode size={24} className="text-accent" />
            </div>
            <div>
              <p className="text-white font-medium">{selectedFile.name}</p>
              <p className="text-xs text-neutral-500 mt-0.5 font-mono">
                {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB
              </p>
            </div>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onFileSelect(null);
              }}
              className="flex items-center gap-1 text-xs text-neutral-500 hover:text-risk-critical transition-colors"
            >
              <X size={12} />
              Supprimer
            </button>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-3">
            <div className="w-14 h-14 rounded-xl bg-neutral-800 flex items-center justify-center">
              <UploadCloud size={28} className="text-neutral-500" />
            </div>
            <div>
              <p className="text-neutral-300 font-medium">
                Glisser-déposer votre fichier APK ici
              </p>
              <p className="text-xs text-neutral-600 mt-1">ou cliquez pour sélectionner</p>
            </div>
            <span className="text-xs font-mono text-neutral-600 bg-neutral-800 px-2 py-1 rounded">
              .apk uniquement
            </span>
          </div>
        )}
      </div>

      {error && (
        <div className="flex items-center gap-2 text-risk-critical text-sm bg-risk-critical/5 border border-risk-critical/20 rounded-lg px-3 py-2">
          <AlertCircle size={14} className="flex-shrink-0" />
          {error}
        </div>
      )}
    </div>
  );
};

export default UploadCard;
