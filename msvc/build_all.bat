
msbuild /t:clean,build /property:Configuration=Debug;Platform=Win32
msbuild /t:clean,build /property:Configuration=Release;Platform=Win32
msbuild /t:clean,build /property:Configuration=Debug;Platform=x64
msbuild /t:clean,build /property:Configuration=Release;Platform=x64
