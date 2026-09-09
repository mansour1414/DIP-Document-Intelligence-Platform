"use client";

import { useCallback, useState } from "react";
import Link from "next/link";
import { Upload, File, X, GripVertical, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface FileItem {
  id: string;
  file: File;
  name: string;
  size: number;
}

export default function MergePDFPage() {
  const [files, setFiles] = useState<FileItem[]>([]);
  const [processing, setProcessing] = useState(false);
  const [dragActive, setDragActive] = useState(false);

  const addFiles = useCallback((newFiles: File[]) => {
    const items: FileItem[] = newFiles.map((file) => ({
      id: crypto.randomUUID(),
      file,
      name: file.name,
      size: file.size,
    }));
    setFiles((prev) => [...prev, ...items]);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    const droppedFiles = Array.from(e.dataTransfer.files).filter(
      (f) => f.type === "application/pdf" || f.type.startsWith("image/")
    );
    addFiles(droppedFiles);
  }, [addFiles]);

  const handleFileInput = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      addFiles(Array.from(e.target.files || []));
    },
    [addFiles]
  );

  const removeFile = (id: string) => {
    setFiles((prev) => prev.filter((f) => f.id !== id));
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const handleMerge = async () => {
    if (files.length < 2) return;
    setProcessing(true);
    // TODO: Implement client-side merge with pdf-lib
    setTimeout(() => {
      setProcessing(false);
      alert("Merge functionality coming soon! Using pdf-lib for client-side merging.");
    }, 2000);
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="border-b bg-white sticky top-0 z-50">
        <div className="container mx-auto px-4 h-16 flex items-center gap-4">
          <Link
            href="/"
            className="flex items-center gap-2 font-bold"
          >
            <span className="bg-blue-600 text-white px-2 py-1 rounded-lg text-xs">
              DIP
            </span>
          </Link>
          <span className="text-gray-300">|</span>
          <h1 className="font-semibold">Merge PDF</h1>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8 max-w-3xl">
        <Card>
          <CardHeader>
            <CardTitle className="text-2xl">Merge PDF Files</CardTitle>
            <p className="text-gray-500">
              Combine multiple PDF files into a single document. All processing
              happens in your browser — your files never leave your device.
            </p>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Drop Zone */}
            <div
              className={`border-2 border-dashed rounded-xl p-12 text-center transition-colors ${
                dragActive
                  ? "border-blue-500 bg-blue-50"
                  : "border-gray-300 hover:border-gray-400"
              }`}
              onDragOver={(e) => {
                e.preventDefault();
                setDragActive(true);
              }}
              onDragLeave={() => setDragActive(false)}
              onDrop={handleDrop}
            >
              <Upload className="w-12 h-12 mx-auto text-gray-400 mb-4" />
              <p className="text-lg font-medium mb-2">
                Drag & drop your files here
              </p>
              <p className="text-sm text-gray-500 mb-4">or</p>
              <label>
                <input
                  type="file"
                  multiple
                  accept=".pdf,image/*"
                  onChange={handleFileInput}
                  className="hidden"
                />
                <Button variant="outline" asChild>
                  <span className="cursor-pointer">Browse Files</span>
                </Button>
              </label>
              <p className="text-xs text-gray-400 mt-4">
                Supports PDF, JPG, PNG — Maximum file size: 100MB
              </p>
            </div>

            {/* File List */}
            {files.length > 0 && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="font-medium">
                    {files.length} file{files.length !== 1 ? "s" : ""} selected
                  </h3>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setFiles([])}
                    className="text-red-500 hover:text-red-600"
                  >
                    Clear All
                  </Button>
                </div>
                <div className="space-y-2">
                  {files.map((item, index) => (
                    <div
                      key={item.id}
                      className="flex items-center gap-3 p-3 bg-white border rounded-lg"
                    >
                      <GripVertical className="w-4 h-4 text-gray-400 cursor-grab" />
                      <span className="text-sm font-medium text-gray-400 w-6">
                        {index + 1}
                      </span>
                      <File className="w-5 h-5 text-red-500" />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">
                          {item.name}
                        </p>
                        <p className="text-xs text-gray-500">
                          {formatSize(item.size)}
                        </p>
                      </div>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => removeFile(item.id)}
                        className="h-8 w-8"
                      >
                        <X className="w-4 h-4" />
                      </Button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Merge Button */}
            {files.length >= 2 && (
              <Button
                onClick={handleMerge}
                disabled={processing}
                className="w-full"
                size="lg"
              >
                {processing ? (
                  "Processing..."
                ) : (
                  <>
                    <Download className="w-4 h-4" />
                    Merge {files.length} Files
                  </>
                )}
              </Button>
            )}

            {files.length === 1 && (
              <p className="text-center text-sm text-gray-500">
                Add at least one more file to merge
              </p>
            )}
          </CardContent>
        </Card>

        {/* Info Section */}
        <div className="mt-8 grid md:grid-cols-3 gap-4">
          <div className="text-center p-4">
            <div className="text-2xl mb-2">🔒</div>
            <h4 className="font-medium text-sm">100% Private</h4>
            <p className="text-xs text-gray-500">
              Files are processed in your browser
            </p>
          </div>
          <div className="text-center p-4">
            <div className="text-2xl mb-2">⚡</div>
            <h4 className="font-medium text-sm">Fast Processing</h4>
            <p className="text-xs text-gray-500">
              No upload needed, instant merge
            </p>
          </div>
          <div className="text-center p-4">
            <div className="text-2xl mb-2">📱</div>
            <h4 className="font-medium text-sm">Works Everywhere</h4>
            <p className="text-xs text-gray-500">
              Desktop, tablet, and mobile
            </p>
          </div>
        </div>
      </main>
    </div>
  );
}
