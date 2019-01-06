% something
server(
	A = #some_record {
		var = B,
		var2 = C,
		var3 = D,
		var4 = F
	}) ->
    io:format("~p~n", [erlang:memory()]),
	try (receive
		BBB when is_record(BBB, some_record) ->