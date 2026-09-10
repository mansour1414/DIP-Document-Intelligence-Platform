import { CreateBucketCommand, HeadBucketCommand, S3Client } from "@aws-sdk/client-s3";
const bucket = process.env.STORAGE_BUCKET ?? "dip-test";
const client = new S3Client({ endpoint: process.env.STORAGE_ENDPOINT, region: process.env.STORAGE_REGION ?? "us-east-1", forcePathStyle: true, credentials: { accessKeyId: process.env.STORAGE_ACCESS_KEY ?? "minioadmin", secretAccessKey: process.env.STORAGE_SECRET_KEY ?? "minioadmin" } });
try { await client.send(new HeadBucketCommand({ Bucket: bucket })); } catch { await client.send(new CreateBucketCommand({ Bucket: bucket })); }
console.log(`test bucket ready: ${bucket}`);

