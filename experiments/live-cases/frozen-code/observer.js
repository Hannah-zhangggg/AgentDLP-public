import fs from "node:fs";
export default async () => {
 const root=process.env.ADLP_OBSERVER_RUN;
 if(!root) throw new Error("Missing observer run directory");
 const append=(name,v)=>fs.appendFileSync(root+"/"+name,JSON.stringify({...v,time_ms:Date.now()})+"\n");
 append("hook-lifecycle.jsonl",{kind:"plugin_loaded"});
 return {
  "tool.execute.before":async(input,output)=>{
   if(!input.tool.startsWith("native_")) return;
   append("hook-before.jsonl",{...input,arguments:structuredClone(output.args)});
  },
  "tool.execute.after":async(input,output)=>{
   if(!input.tool.startsWith("native_")) return;
   append("hook-after.jsonl",{...input,received:structuredClone(output)});
  }
 };
};
