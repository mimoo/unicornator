
  let create_table buffer_kind =
    { buffer_kind ;
      last_id = 0 ;
      instances = Hashtbl.create 10 ; (* should trigger *)
      zombies = Hashtbl.create ~random:true 10 (* should not trigger *)}
